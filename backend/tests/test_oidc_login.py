"""OIDC bearer login (backend/oidc.py) against a local fake issuer and a real MongoDB.

The issuer is an in-process RSA key whose JWKS is served through an httpx MockTransport;
users are real Beanie documents, because the guarantees under test (same ObjectId, the
partial unique index, the atomic email link) only exist in the real database.
"""

import base64
import hashlib
import hmac
import json
import os
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import jwt
import pytest
from beanie import init_beanie
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI, HTTPException, WebSocketDisconnect
from fastapi_users.db import BeanieUserDatabase
from google.protobuf import timestamp_pb2
from motor.motor_asyncio import AsyncIOMotorClient

from backend import auth, oidc
from backend.audio_contract.v2 import audio_pb2
from backend.audio_contract.v2.codec import serialize_client_control_json
from backend.controllers import audio_v2_controller
from backend.models.user import User, UserRead, UserUpdate

ISSUER = "https://door.example.com"
AUDIENCE = "chronicle-test-client"
KID = "test-kid"


class FakeIssuer:
    """RSA key + JWKS endpoint. ``down = True`` makes the JWKS unreachable."""

    def __init__(self):
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.down = False
        self.jwks_requests = 0

    def jwks(self) -> dict:
        jwk = jwt.algorithms.RSAAlgorithm.to_jwk(self.key.public_key(), as_dict=True)
        return {"keys": [{**jwk, "kid": KID, "alg": "RS256", "use": "sig"}]}

    def transport(self) -> httpx.MockTransport:
        def handle(request: httpx.Request) -> httpx.Response:
            self.jwks_requests += 1
            if self.down:
                raise httpx.ConnectError("connection refused", request=request)
            if request.url.path == oidc.JWKS_PATH:
                return httpx.Response(200, json=self.jwks())
            return httpx.Response(404)

        return httpx.MockTransport(handle)

    def token(self, *, key=None, kid=KID, omit=(), **claims) -> str:
        now = int(time.time())
        payload = {
            "sub": "casdoor-user-1",
            "name": "alice",
            "displayName": "Alice",
            "email": "alice@example.com",
            "tokenType": "access-token",
            "iss": ISSUER,
            "aud": [AUDIENCE],
            "iat": now,
            "exp": now + 3600,
            **claims,
        }
        payload = {k: v for k, v in payload.items() if k not in omit}
        return jwt.encode(
            payload, key or self.key, algorithm="RS256", headers={"kid": kid}
        )


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unsigned_or_hmac(header: dict, claims: dict, secret: bytes | None) -> str:
    """Hand-built JWTs PyJWT refuses to make: alg none, or HS256 keyed with the public key."""
    signing_input = (
        f"{_b64(json.dumps(header).encode())}.{_b64(json.dumps(claims).encode())}"
    )
    signature = (
        b""
        if secret is None
        else hmac.new(secret, signing_input.encode(), hashlib.sha256).digest()
    )
    return f"{signing_input}.{_b64(signature)}"


@pytest.fixture
async def users(mongo_service):
    client = AsyncIOMotorClient(os.getenv("MONGODB_URI", "mongodb://localhost:27018"))
    database = client["test_oidc_login_db"]
    await init_beanie(database=database, document_models=[User])
    yield database
    await client.drop_database(database.name)
    client.close()


@pytest.fixture
def issuer(users):
    fake = FakeIssuer()
    oidc.set_verifier(
        oidc.OIDCVerifier(
            oidc.OIDCConfig(ISSUER, AUDIENCE, ISSUER + oidc.JWKS_PATH), fake.transport()
        )
    )
    yield fake
    oidc.set_verifier(None)


def _allow_unverified_email_link():
    verifier = oidc.get_verifier()
    config = oidc.OIDCConfig(
        ISSUER, AUDIENCE, verifier.config.jwks_url, link_unverified_email=True
    )
    verifier.config = config


async def _read(token: str):
    manager = auth.UserManager(BeanieUserDatabase(User))
    return await auth.get_jwt_strategy().read_token(token, manager)


async def _existing_user(email="alice@example.com", **fields) -> User:
    user = User(email=email, hashed_password="x", **fields)
    await user.insert()
    return user


def test_config_is_off_unless_issuer_and_audience_are_set(monkeypatch):
    monkeypatch.delenv("OIDC_ISSUER", raising=False)
    monkeypatch.setenv("OIDC_AUDIENCE", AUDIENCE)
    assert oidc.OIDCConfig.from_env() is None
    monkeypatch.setenv("OIDC_ISSUER", ISSUER + "/")
    config = oidc.OIDCConfig.from_env()
    assert (config.issuer, config.jwks_url, config.link_unverified_email) == (
        ISSUER,
        ISSUER + "/.well-known/jwks",
        False,
    )
    monkeypatch.setenv("OIDC_JWKS_URL", "http://casdoor:8000/.well-known/jwks")
    assert oidc.OIDCConfig.from_env().jwks_url == "http://casdoor:8000/.well-known/jwks"


# ── finding the user ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_known_oidc_sub_resolves_to_the_same_objectid(issuer):
    existing = await _existing_user(oidc_sub="casdoor-user-1")
    user = await _read(issuer.token())
    assert user.id == existing.id
    assert user.user_id == str(existing.id)


@pytest.mark.asyncio
async def test_first_sight_creates_a_normal_user_once(issuer):
    first = await _read(
        issuer.token(roles=[{"name": "admin"}], is_superuser=True, isAdmin=True)
    )
    assert first is not None
    assert first.oidc_sub == "casdoor-user-1"
    assert (first.is_superuser, first.is_active) == (False, True)
    again = await _read(issuer.token())
    assert again.id == first.id
    assert await User.find({"oidc_sub": "casdoor-user-1"}).count() == 1


@pytest.mark.asyncio
async def test_unverified_email_never_links_or_claims_the_address(issuer):
    existing = await _existing_user()
    user = await _read(issuer.token())
    assert user.id != existing.id
    assert user.email.endswith("@" + oidc.PLACEHOLDER_EMAIL_DOMAIN)
    assert (await User.get(existing.id)).oidc_sub is None


@pytest.mark.asyncio
@pytest.mark.parametrize("claim", ["email_verified", "emailVerified"])
async def test_verified_email_links_the_existing_account(issuer, claim):
    existing = await _existing_user(email="Alice@Example.com")
    user = await _read(issuer.token(**{claim: True}))
    assert user.id == existing.id
    assert (await User.get(existing.id)).oidc_sub == "casdoor-user-1"


@pytest.mark.asyncio
async def test_unverified_email_links_only_when_the_setting_allows_it(issuer):
    existing = await _existing_user()
    _allow_unverified_email_link()
    user = await _read(issuer.token())
    assert user.id == existing.id


@pytest.mark.asyncio
async def test_email_never_links_to_a_superuser(issuer):
    await _existing_user(is_superuser=True)
    assert await _read(issuer.token(email_verified=True)) is None
    assert await User.find({"oidc_sub": "casdoor-user-1"}).count() == 0


@pytest.mark.asyncio
async def test_email_never_relinks_an_account_owned_by_another_sub(issuer):
    owned = await _existing_user(oidc_sub="someone-else")
    assert await _read(issuer.token(email_verified=True)) is None
    assert (await User.get(owned.id)).oidc_sub == "someone-else"


@pytest.mark.asyncio
async def test_inactive_linked_user_is_refused(issuer):
    await _existing_user(oidc_sub="casdoor-user-1", is_active=False)
    assert await _read(issuer.token()) is None


# ── refusing tokens ───────────────────────────────────────────────────────────


def _bad_tokens(issuer: FakeIssuer) -> dict[str, str]:
    now = int(time.time())
    claims = {
        "sub": "casdoor-user-1",
        "iss": ISSUER,
        "aud": AUDIENCE,
        "exp": now + 3600,
    }
    public_pem = issuer.key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return {
        "wrong_audience": issuer.token(aud=["another-client"]),
        "expired": issuer.token(exp=now - 60, iat=now - 3700),
        "refresh_token": issuer.token(tokenType="refresh-token"),
        "id_token": issuer.token(tokenType="id-token"),
        "no_exp": issuer.token(omit=("exp",)),
        "wrong_key": issuer.token(key=other_key),
        "alg_none": _unsigned_or_hmac({"alg": "none", "kid": KID}, claims, None),
        "hs256_public_key": _unsigned_or_hmac(
            {"alg": "HS256", "kid": KID, "typ": "JWT"}, claims, public_pem
        ),
        # Not the issuer: judged as Chronicle's own HS256 JWT, which it is not.
        "wrong_issuer": issuer.token(iss="https://evil.example.com"),
    }


@pytest.mark.asyncio
async def test_bad_tokens_are_refused_and_create_nobody(issuer):
    for name, token in _bad_tokens(issuer).items():
        assert await _read(token) is None, name
    assert await User.find_all().count() == 0


@pytest.mark.asyncio
async def test_junk_kids_do_not_hammer_the_issuer(issuer):
    await _read(issuer.token())  # warm the cache
    before = issuer.jwks_requests
    for i in range(20):
        try:
            await _read(issuer.token(kid=f"junk-{i}"))
        except HTTPException:
            pass  # rate-limited unknown kid: retryable, not a verdict
    assert issuer.jwks_requests - before <= 1


# ── issuer unreachable ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_unreachable_jwks_is_503_not_invalid_credentials(issuer):
    issuer.down = True
    with pytest.raises(HTTPException) as caught:
        await _read(issuer.token())
    assert caught.value.status_code == 503
    user, failure = await auth.websocket_auth(
        SimpleNamespace(headers={}), issuer.token()
    )
    assert (user, failure) == (None, "auth_unavailable")


# ── entry points ──────────────────────────────────────────────────────────────


def _users_app() -> FastAPI:
    app = FastAPI()
    app.include_router(
        auth.fastapi_users.get_users_router(UserRead, UserUpdate), prefix="/users"
    )
    return app


async def _get_me(token: str) -> httpx.Response:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=_users_app()),
        base_url="http://chronicle.test",
    ) as client:
        return await client.get(
            "/users/me", headers={"Authorization": f"Bearer {token}"}
        )


@pytest.mark.asyncio
async def test_users_me_returns_the_objectid_for_an_oidc_bearer(issuer):
    first = await _get_me(issuer.token())
    second = await _get_me(issuer.token())
    assert first.status_code == 200
    user_id = first.json()["id"]
    assert len(user_id) == 24 and int(user_id, 16) >= 0
    assert second.json()["id"] == user_id
    assert first.json()["is_superuser"] is False
    assert (await _get_me(issuer.token(tokenType="refresh-token"))).status_code == 401
    issuer.down = True
    oidc.set_verifier(
        oidc.OIDCVerifier(oidc.get_verifier().config, issuer.transport())
    )  # cold cache
    assert (await _get_me(issuer.token())).status_code == 503


@pytest.mark.asyncio
async def test_own_jwt_login_still_works(issuer):
    user = await _existing_user()
    token = await auth.get_jwt_strategy().write_token(user)
    assert (await _read(token)).id == user.id
    assert (await _get_me(token)).json()["id"] == str(user.id)


class HelloWebSocket:
    """Just enough of a WebSocket for the audio-v2 hello."""

    def __init__(self, token: str):
        self.scope = {"subprotocols": ["chronicle.audio.v2"]}
        self.headers = {}
        self._hello = serialize_client_control_json(
            audio_pb2.ClientControl(
                event_id=audio_pb2.EventId(value="hello-1"),
                sent_at=timestamp_pb2.Timestamp(seconds=int(time.time())),
                hello=audio_pb2.ClientHello(
                    bearer_token=token,
                    source_id=audio_pb2.CaptureSourceId(value="phone-1"),
                    device_kind=audio_pb2.DEVICE_KIND_IOS_PHONE,
                    display_name="phone",
                ),
            )
        )
        self.sent = []
        self.closed = None

    async def accept(self, *, subprotocol):
        pass

    async def receive_text(self):
        return self._hello

    async def send_text(self, value):
        self.sent.append(json.loads(value))

    async def close(self, *, code, reason):
        self.closed = (code, reason)


@pytest.mark.asyncio
async def test_audio_v2_hello_with_an_oidc_token_binds_the_linked_user(
    issuer, monkeypatch
):
    existing = await _existing_user(oidc_sub="casdoor-user-1")
    # Stop right after authentication: the client state is what stamps conversations.
    create_client_state = AsyncMock(side_effect=WebSocketDisconnect())
    monkeypatch.setattr(audio_v2_controller, "create_client_state", create_client_state)
    token = issuer.token()
    assert (
        len(token) > 255
    )  # past the old id-sized hello limit, like a real Casdoor token
    await audio_v2_controller.handle_audio_v2_websocket(HelloWebSocket(token))
    bound_user = create_client_state.await_args.args[1]
    assert bound_user.user_id == str(existing.id)


@pytest.mark.asyncio
async def test_audio_v2_hello_when_the_issuer_is_down_is_retryable(issuer, monkeypatch):
    issuer.down = True
    create_client_state = AsyncMock()
    monkeypatch.setattr(audio_v2_controller, "create_client_state", create_client_state)
    websocket = HelloWebSocket(issuer.token())
    await audio_v2_controller.handle_audio_v2_websocket(websocket)
    create_client_state.assert_not_awaited()
    assert websocket.closed == (1013, "authentication unavailable")
    assert websocket.sent[-1]["error"]["code"] == "PROTOCOL_ERROR_CODE_INTERNAL"
