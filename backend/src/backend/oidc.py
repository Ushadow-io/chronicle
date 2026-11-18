"""Standard OIDC bearer login (e.g. Casdoor): validate an access token, then find or create its user.

Off unless ``OIDC_ISSUER`` and ``OIDC_AUDIENCE`` are both set. See docs/oidc-login.md.

- ``OIDC_ISSUER``: must equal the token ``iss`` exactly (the issuer's EXTERNAL URL).
- ``OIDC_AUDIENCE``: the client id; must be in the token ``aud``.
- ``OIDC_JWKS_URL``: optional, default ``{OIDC_ISSUER}/.well-known/jwks`` (Casdoor's path).
  Set it when Chronicle reaches the issuer at a different (internal) address.
- ``OIDC_LINK_UNVERIFIED_EMAIL``: ``true`` trusts the token's email even when the token does not
  say it is verified. Default off: without proof of ownership an email match is an account
  takeover. It relaxes the TOKEN side only, never the local-account check below.

Token checks: RS256 only, key from the issuer's JWKS by ``kid``, ``iss``/``aud``/``exp``/``sub``
required, and ``tokenType`` (Casdoor) must be ``access-token`` when present, so refresh and id
tokens are not accepted as bearers. A token the issuer did not sign is ``None`` (401); a JWKS
that cannot be fetched raises ``OIDCUnavailableError`` (503), never "invalid credentials".

Users: matched by ``oidc_sub`` == token ``sub``. A first-time ``sub`` links to the account with
the same email only when the token email is trusted (see above) AND that local account is
``is_verified`` (else anyone could pre-register a victim's email locally and inherit the
victim's sign-in), not a superuser and not linked to another ``sub``. Any of those failing is
a refusal (an admin links by setting ``users.oidc_sub``), never a second account with the same
email. No local account with that email: a new normal user is created. Claims never grant
superuser. The user's Mongo ObjectId stays its id everywhere.
"""

import asyncio
import hashlib
import logging
import os
import secrets
import time
from dataclasses import dataclass
from typing import Optional

import httpx
import jwt
from fastapi_users.db import BeanieUserDatabase
from fastapi_users.password import PasswordHelper
from pydantic import EmailStr, TypeAdapter, ValidationError
from pymongo.errors import DuplicateKeyError

from backend.models.user import User, get_user_by_oidc_sub

logger = logging.getLogger(__name__)

JWKS_PATH = "/.well-known/jwks"
ALGORITHM = "RS256"
REQUIRED_CLAIMS = ["exp", "iss", "aud", "sub"]
# Casdoor signs access, refresh and id tokens with the same key; only `tokenType` tells them apart.
TOKEN_TYPE_CLAIM = "tokenType"
ACCESS_TOKEN_TYPE = "access-token"
# Standard OIDC claim, and Casdoor's own user field (it puts the user object in the token).
EMAIL_VERIFIED_CLAIMS = ("email_verified", "emailVerified")
# Accounts created for a token without a usable trusted email get this placeholder domain.
PLACEHOLDER_EMAIL_DOMAIN = "no-email.oidc.chronicle"

JWKS_TTL_SECONDS = 3600.0
# Unknown `kid`s come from unauthenticated callers: at most one refetch per interval.
MIN_REFETCH_INTERVAL_SECONDS = 5.0
# After a failed fetch nothing contacts the issuer again for this long.
FAILED_FETCH_BACKOFF_SECONDS = 3.0

_email = TypeAdapter(EmailStr)


class OIDCUnavailableError(Exception):
    """The issuer's signing keys could not be fetched: the token was never judged (503, retry)."""


class OIDCTokenError(Exception):
    """The token is not a valid access token from the configured issuer (401)."""


@dataclass(frozen=True)
class OIDCConfig:
    issuer: str
    audience: str
    jwks_url: str
    link_unverified_email: bool = False

    @classmethod
    def from_env(cls) -> Optional["OIDCConfig"]:
        issuer = os.getenv("OIDC_ISSUER", "").strip().rstrip("/")
        audience = os.getenv("OIDC_AUDIENCE", "").strip()
        if not issuer or not audience:
            return None
        jwks_url = os.getenv("OIDC_JWKS_URL", "").strip() or issuer + JWKS_PATH
        link = os.getenv("OIDC_LINK_UNVERIFIED_EMAIL", "").strip().lower() == "true"
        return cls(issuer, audience, jwks_url, link)


class JWKSCache:
    """Keys by ``kid``; refetched after the TTL and on an unknown ``kid`` (key rotation), rate-limited.

    A kid is "unknown" (OIDCTokenError) only if a fetch that started after the lookup began lacked
    it; otherwise (rate-limited, issuer down) it is OIDCUnavailableError, so junk kids sent first
    can neither hammer the issuer nor log out a user whose key really rotated. Stale keys keep
    being served when a refresh fails; an empty cache that cannot be filled is unavailable.
    """

    def __init__(self, url: str, transport: Optional[httpx.AsyncBaseTransport] = None):
        self._url = url
        self._transport = transport
        self._keys: dict[str, dict] = {}
        self._fetched_at: Optional[float] = None
        self._failed_at: Optional[float] = None
        self._kid_refetch_at: Optional[float] = None
        self._keys_seq = 0  # number of the fetch the current keys came from
        self._started = 0  # fetches started so far
        self._attempts = 0  # fetches finished, so lock waiters can share an outcome
        self._lock = asyncio.Lock()

    def _is_stale(self) -> bool:
        return (
            self._fetched_at is None
            or time.monotonic() - self._fetched_at > JWKS_TTL_SECONDS
        )

    def _in_backoff(self) -> bool:
        return (
            self._failed_at is not None
            and time.monotonic() - self._failed_at < FAILED_FETCH_BACKOFF_SECONDS
        )

    async def _fetch(self) -> None:
        try:
            async with httpx.AsyncClient(
                transport=self._transport, timeout=10
            ) as client:
                response = await client.get(self._url)
                response.raise_for_status()
                keys = response.json().get("keys", [])
        except (httpx.HTTPError, ValueError, AttributeError) as exc:
            logger.warning(f"OIDC JWKS fetch from {self._url} failed: {exc}")
            raise OIDCUnavailableError(
                "Could not fetch the sign-in provider's keys"
            ) from exc
        self._keys = {k["kid"]: k for k in keys if isinstance(k, dict) and k.get("kid")}
        self._fetched_at = time.monotonic()

    async def _refresh(self) -> None:
        seen = self._attempts
        async with self._lock:
            if self._attempts != seen:  # another lookup fetched while we waited
                if self._failed_at is not None:
                    raise OIDCUnavailableError(
                        "Could not fetch the sign-in provider's keys"
                    )
                return
            if self._in_backoff():
                raise OIDCUnavailableError(
                    "Could not fetch the sign-in provider's keys"
                )
            self._started += 1
            seq = self._started
            try:
                await self._fetch()
            except OIDCUnavailableError:
                self._failed_at = time.monotonic()
                raise
            finally:
                self._attempts += 1
            self._keys_seq, self._failed_at = seq, None

    def _kid_refetch_allowed(self) -> bool:
        if self._lock.locked():
            return True  # a fetch is in flight; waiting on it costs the issuer nothing
        now = time.monotonic()
        if (
            self._kid_refetch_at is not None
            and now - self._kid_refetch_at < MIN_REFETCH_INTERVAL_SECONDS
        ):
            return False
        self._kid_refetch_at = now
        return True

    async def get_key(self, kid: str) -> jwt.PyJWK:
        arrived = self._started
        if self._is_stale():
            try:
                await self._refresh()
            except OIDCUnavailableError:
                if not self._keys:
                    raise
                logger.warning("OIDC JWKS refresh failed; serving the last keys")
        elif kid not in self._keys and self._kid_refetch_allowed():
            await self._refresh()
        raw = self._keys.get(kid)
        if raw is None:
            if self._keys_seq > arrived:
                raise OIDCTokenError("Unknown token signing key")
            raise OIDCUnavailableError(
                "Sign-in provider keys are being refreshed, retry shortly"
            )
        try:
            return jwt.PyJWK(raw)
        except jwt.PyJWKError as exc:
            raise OIDCTokenError("Unusable token signing key") from exc


class OIDCVerifier:
    def __init__(
        self, config: OIDCConfig, transport: Optional[httpx.AsyncBaseTransport] = None
    ):
        self.config = config
        self._jwks = JWKSCache(config.jwks_url, transport)

    def is_candidate(self, token: str) -> bool:
        """Whether this token claims to come from the configured issuer (unverified peek).

        Only routes the token: a match is then fully verified and never falls back to
        Chronicle's own JWT check, and a non-match is judged by that check alone.
        """
        try:
            claims = jwt.decode(token, options={"verify_signature": False})
        except jwt.InvalidTokenError:
            return False
        return isinstance(claims, dict) and claims.get("iss") == self.config.issuer

    async def verify(self, token: str) -> dict:
        """Claims of a valid access token. OIDCTokenError / OIDCUnavailableError otherwise."""
        try:
            header = jwt.get_unverified_header(token)
        except jwt.InvalidTokenError as exc:
            raise OIDCTokenError("Invalid token format") from exc
        kid = header.get("kid")
        if header.get("alg") != ALGORITHM or not kid:
            raise OIDCTokenError(f"Token must be {ALGORITHM} with a key id")
        key = await self._jwks.get_key(kid)
        if key.key_type != "RSA":
            raise OIDCTokenError("Signing key is not an RSA key")
        try:
            claims = jwt.decode(
                token,
                key.key,
                algorithms=[ALGORITHM],
                audience=self.config.audience,
                issuer=self.config.issuer,
                options={"require": REQUIRED_CLAIMS},
            )
        except jwt.InvalidTokenError as exc:
            raise OIDCTokenError(f"Token validation failed: {exc}") from exc
        token_type = claims.get(TOKEN_TYPE_CLAIM, ACCESS_TOKEN_TYPE)
        if token_type != ACCESS_TOKEN_TYPE:
            raise OIDCTokenError(
                f"Not an access token ({TOKEN_TYPE_CLAIM}={token_type})"
            )
        if not isinstance(claims["sub"], str) or not claims["sub"]:
            raise OIDCTokenError("Token has no subject")
        return claims


_verifier: Optional[OIDCVerifier] = None
_verifier_loaded = False


def get_verifier() -> Optional[OIDCVerifier]:
    """The process-wide verifier, or None when OIDC login is not configured."""
    global _verifier, _verifier_loaded
    if not _verifier_loaded:
        config = OIDCConfig.from_env()
        _verifier = OIDCVerifier(config) if config else None
        _verifier_loaded = True
        if config:
            logger.info(f"OIDC login enabled for issuer {config.issuer}")
    return _verifier


def set_verifier(verifier: Optional[OIDCVerifier]) -> None:
    """Replace the process-wide verifier (tests)."""
    global _verifier, _verifier_loaded
    _verifier, _verifier_loaded = verifier, True


def _trusted_email(claims: dict, config: OIDCConfig) -> Optional[str]:
    """The token's email when it may identify an existing account, else None."""
    raw = claims.get("email")
    if not isinstance(raw, str) or not raw:
        return None
    try:
        email = str(_email.validate_python(raw))
    except ValidationError:
        return None
    verified = any(claims.get(name) is True for name in EMAIL_VERIFIED_CLAIMS)
    return email if verified or config.link_unverified_email else None


# Same message for every refused link: the caller only gets a 401, and the log names the reason.
LINK_REFUSED = "Sign-in matches an existing account that cannot be linked automatically"


def _link_refusal(user: User) -> Optional[str]:
    """Why ``user`` must not be linked by email, or None when it may be."""
    if user.is_superuser:
        return "it is a superuser (an email claim never confers superuser)"
    if user.oidc_sub:
        return "it is already linked to another sub"
    if not user.is_verified:
        # A local sign-up does not prove the email: whoever registered it would share the
        # victim's account once the victim signs in through the issuer (pre-hijacking).
        return "its email is not verified locally"
    return None


async def _link_by_email(email: str, sub: str) -> Optional[User]:
    user = await BeanieUserDatabase(User).get_by_email(email)
    if user is None:
        return None
    refusal = _link_refusal(user)
    if refusal is not None:
        logger.warning(
            f"OIDC: not linking sub {sub} to existing user {user.user_id} by email: "
            f"{refusal}. An admin can link it by setting users.oidc_sub = {sub!r} on that "
            f"account after confirming who owns it."
        )
        raise OIDCTokenError(LINK_REFUSED)
    result = await User.get_pymongo_collection().update_one(
        {"_id": user.id, "oidc_sub": None}, {"$set": {"oidc_sub": sub}}
    )
    if result.modified_count != 1:
        return await get_user_by_oidc_sub(sub)
    logger.info(
        f"OIDC: linked sub {sub} to existing user {user.user_id} by verified email"
    )
    user.oidc_sub = sub
    return user


def _display_name(claims: dict) -> Optional[str]:
    for name in ("displayName", "name", "preferred_username"):
        value = claims.get(name)
        if isinstance(value, str) and value:
            return value
    return None


async def _create_user(claims: dict, email: Optional[str]) -> Optional[User]:
    sub = claims["sub"]
    if email is None:
        digest = hashlib.sha256(sub.encode()).hexdigest()[:24]
        email = f"oidc-{digest}@{PLACEHOLDER_EMAIL_DOMAIN}"
    user = User(
        email=email,
        # Unusable password: this account signs in through the issuer only.
        hashed_password=PasswordHelper().hash(secrets.token_urlsafe(32)),
        is_active=True,
        is_superuser=False,
        is_verified=False,
        display_name=_display_name(claims),
        oidc_sub=sub,
    )
    try:
        await user.insert()
    except DuplicateKeyError:
        # A concurrent first request created it, or the email is taken (untrusted, so no link).
        existing = await get_user_by_oidc_sub(sub)
        if existing is None:
            logger.warning(
                f"OIDC: cannot create a user for sub {sub}: email already in use"
            )
            raise OIDCTokenError("Email belongs to another account") from None
        return existing
    logger.info(f"OIDC: created user {user.user_id} for sub {sub}")
    return user


async def resolve_user(claims: dict, config: OIDCConfig) -> Optional[User]:
    """The user for verified claims: by ``oidc_sub``, then a trusted email link, else a new user."""
    sub = claims["sub"]
    user = await get_user_by_oidc_sub(sub)
    if user is None:
        email = _trusted_email(claims, config)
        if email is not None:
            user = await _link_by_email(email, sub)
        if user is None:
            user = await _create_user(claims, email)
    return user if user is not None and user.is_active else None


async def read_oidc_token(token: str) -> tuple[bool, Optional[User]]:
    """(handled, user). ``handled`` is False when OIDC is off or the token is not the issuer's.

    A handled token that fails verification yields ``(True, None)``; an unreachable JWKS raises
    OIDCUnavailableError.
    """
    verifier = get_verifier()
    if verifier is None or not verifier.is_candidate(token):
        return False, None
    try:
        claims = await verifier.verify(token)
        return True, await resolve_user(claims, verifier.config)
    except OIDCTokenError as exc:
        logger.info(f"OIDC token rejected: {exc}")
        return True, None
