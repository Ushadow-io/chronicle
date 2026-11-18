# OIDC (Casdoor) bearer login

Chronicle accepts a standard OIDC access token (for example from Casdoor) as a bearer
credential, next to its own JWTs and API keys. It is off unless configured. Code:
`backend/src/backend/oidc.py`; wiring: `ApiKeyOrJWTStrategy` in `backend/src/backend/auth.py`.

## Settings

| Env | Meaning |
|---|---|
| `OIDC_ISSUER` | Must equal the token `iss` exactly: the issuer's EXTERNAL URL (a trailing `/` is dropped). |
| `OIDC_AUDIENCE` | The client id; must be in the token `aud`. |
| `OIDC_JWKS_URL` | Optional. Default `{OIDC_ISSUER}/.well-known/jwks` (Casdoor's path). Set it to an internal address when Chronicle cannot reach the external one. |
| `OIDC_LINK_UNVERIFIED_EMAIL` | Optional, default `false`. See "Users" below. |

Both `OIDC_ISSUER` and `OIDC_AUDIENCE` must be set, or OIDC login is off.

## Where it applies

Every place Chronicle reads a bearer goes through the same strategy, so all of them accept an
OIDC access token: the `Authorization: Bearer` header (`current_active_user`, `/users/me`, the
API routers), the `?token=` query parameter (`get_user_from_token_param`), the websocket
`token` (`websocket_auth`), the audio v2 `ClientHello.bearer_token`, and
`POST /auth/session/exchange` (a browser session for the token's user). The v2 hello accepts
bearers up to 16 KiB, because Casdoor tokens carry the user object.

## Token checks

- Routing: a token whose (unverified) `iss` equals `OIDC_ISSUER` is judged by OIDC only. Any
  other token is judged by Chronicle's own HS256 JWT check only.
- RS256 only, with a `kid`; the key comes from the issuer's JWKS and must be an RSA key. `alg: none`
  and HS256 (for example signed with the public key) are refused.
- `iss`, `aud`, `exp` and `sub` are required and checked.
- Casdoor signs access, refresh and id tokens with the same key. If `tokenType` is present it must
  be `access-token`, so refresh and id tokens are refused as bearers.
- JWKS: cached for an hour, refetched on an unknown `kid` at most once per 5 s, and not refetched
  for 3 s after a failed fetch. Junk `kid`s therefore cannot hammer the issuer.
- A bad token is a 401. A JWKS that cannot be fetched is a 503 ("Sign-in provider unavailable"),
  never "invalid credentials". On the websocket it is the failure reason `auth_unavailable`; in
  the audio v2 hello it is `PROTOCOL_ERROR_CODE_INTERNAL` and close code 1013 (try again later).

## Users

The user id stays the Mongo ObjectId of the `users` document, so conversations are stamped with
`str(user.id)` exactly as for a password or JWT login. The token `sub` is stored in
`users.oidc_sub` (unique among string values: a partial index, because saves write
`oidc_sub: null` and a sparse unique index would still collide on those).

For a valid token:

1. A user whose `oidc_sub` equals `sub`: that user (if active).
2. Else, if the token's email is trusted, the local user with that email (case-insensitive) is
   linked by setting its `oidc_sub`. The token's email is trusted when the token says
   `email_verified: true` (or Casdoor's `emailVerified: true`), or when
   `OIDC_LINK_UNVERIFIED_EMAIL=true`. The link is made only when the LOCAL account is
   trustworthy for that email too: it must be `is_verified`, not a superuser, and not linked to
   another `sub`. Otherwise the sign-in is refused (401, one generic message; the log names the
   account and the reason) and no second account is created. `OIDC_LINK_UNVERIFIED_EMAIL`
   relaxes the token side only; it never bypasses the local-account check.
3. Else (no local user with a trusted email) a new normal user is created: not a superuser,
   `oidc_sub = sub`, an unusable random password, the token's display name, and the token's
   email only if it is trusted. An untrusted email is not stored: the account gets
   `oidc-<hash>@no-email.oidc.chronicle`, so an unverified token can neither take over nor
   squat an address.

Why the local account must be verified: a local sign-up does not prove the email. Without the
check, anyone could register a victim's email locally, keep the password, and share the
victim's account once the victim first signs in through the issuer (account pre-hijacking).
Who is verified: the startup admin (`ADMIN_EMAIL`) and users an admin created or updated with
`is_verified: true`. Self-registered users, and users old Ushadow created on first Casdoor
sign-in, are not; the latter already carry `oidc_sub`, so step 1 finds them.

Why refuse rather than create a separate account: a separate account would silently split the
person's data across two user ids (and two ledger `userId`s), which is hard to merge later. A
refusal is visible and fixed once by an admin. The cost: someone who pre-registers an email
can block that person's first issuer sign-in until an admin links the right account.

To link an account by hand (an administrator, or an unverified local account whose owner you
have confirmed), set that account's `users.oidc_sub` in Mongo to the person's OIDC `sub`.

No claim ever makes a user a superuser.

Why the token's email must be verified: if the issuer lets people register or change an email
without proving they own it, linking by email lets anyone take over the account with that email.

## Who is this user

`GET /users/me` with an OIDC bearer returns the user, `id` being the ObjectId string. Ushadow
uses this to learn which Chronicle user (and so which ledger `userId`) a Casdoor user is.

## Tests

`backend/tests/test_oidc_login.py` (needs MongoDB, see `docs/testing.md`) runs a local fake
issuer: an RSA key whose JWKS is served through an httpx mock transport.
