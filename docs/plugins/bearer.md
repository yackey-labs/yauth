# bearer — JWT access + refresh tokens

The `bearer` plugin issues HS256 JWT access tokens plus opaque refresh tokens
for API/mobile clients that authenticate with `Authorization: Bearer <token>`
instead of a session cookie. (For RS256/ES256 tokens an OIDC RP can verify via
JWKS, that's the OIDC-provider path — see `yauth docs plugins/oidc-provider`.)

## Endpoints (under your mount prefix)

| Method | Path             | Purpose                                        |
| ------ | ---------------- | ---------------------------------------------- |
| POST   | `/token`         | email + password → `{access_token, refresh_token}` |
| POST   | `/token/mfa`     | `pending_session_id` + code → `{access_token, refresh_token}` |
| POST   | `/token/refresh` | rotate the refresh token (family rotation, reuse-revocation) |
| POST   | `/token/revoke`  | revoke a refresh-token family (auth-gated)     |

## Second factor / lockout on `/token`

`/token` runs the same auth-event pipeline as the cookie `/login`
(`login.attempt` → `login.failed` / `login.succeeded`), so plugins that
interpose on login apply to native clients too: `lockout` throttles brute
force, `mfa` steps up, `auditexport`/`webhooks` see the login.

When a handler answers `login.succeeded` with a `RequireMfa` decision (the
`mfa` plugin does this for a user with verified TOTP), `/token` issues **no
tokens** and returns the same step-up body the cookie login returns:

```json
{ "require_mfa": true, "pending_session_id": "…" }
```

The client then completes the challenge at `/token/mfa` with that id plus a
TOTP or backup code (`{"pending_session_id": "…", "code": "123456"}`, plus an
optional `org`), and receives the ordinary `{access_token, refresh_token,
token_type, expires_in}` pair. `/mfa/verify` is the cookie-flow equivalent and
ends in a session cookie a native client cannot carry, which is why the token
exchange lives here.

The pending session is single-use and short-lived (5 minutes): a wrong code
burns it, and the caller must start again at `/token`. `/token/mfa` returns
400 when no `mfa` plugin is loaded — it fails closed rather than waving a
challenge through — and one opaque 401 for an unknown, expired or spent
pending session as well as a wrong code.

`/token/mfa` emits the `login.succeeded` that marks the login **completed** —
the one at `/token` only meant "password verified" — so `lockout` clears its
failure counter and audit/webhook consumers see the finished login. Wrong
codes emit `login.failed`, so MFA brute force is throttled like password
brute force.

**Backwards compatible:** a caller with no second factor enrolled still gets
the token pair from a single `/token` call, byte for byte. A deployment that
wires neither `mfa` nor `lockout` sees no behavioural change.

## What terminates a refresh token

Refresh tokens outlive sessions (30 days by default) and roll forward on every
rotation, so what revokes them matters more than what revokes a cookie. Each of
these revokes **every** refresh token the user holds:

- the user changing their password (`POST /change-password`) or completing a
  reset (`POST /reset-password`). Change-password re-issues the caller's own
  session cookie afterwards, so the device that performed the rotation stays
  signed in; nothing else does;
- an admin banning or suspending the account, and SCIM deprovisioning it;
- SSO back-channel logout and SAML single-logout;
- `POST /token/revoke`, and presenting an already-rotated token (reuse revokes
  the whole family).

Separately, the bearer resolver re-reads the user on **every** request, so a
banned, suspended or not-yet-active account stops authenticating at once even
while its access token is still inside its 15-minute lifetime.

## Wiring (builder API)

```go
ya, err := yauth.New(repo, yauth.NewDefaultConfig()).
    WithJWTSecret(secret).                                   // HS256 secret (>=32 bytes)
    WithPlugin(emailpassword.New(emailpassword.Config{})).  // bearer issues tokens for these users
    WithPlugin(bearer.New(bearer.Config{
        AccessTTL:  15 * time.Minute,   // default 15m
        RefreshTTL: 720 * time.Hour,    // default 30d
        Issuer:     "yauth",            // JWT "iss"
        // Audience: "my-api",          // optional "aud", enforced on verify
    })).
    Build()
```

`bearer.Config.JWTSecret` may be set directly; if left empty the plugin uses
`host.JWTSecret()` from `WithJWTSecret(...)`. **A secret is required** — the
plugin panics at wiring time if neither is present. Generate one with
`yauth gen-secrets`.

## Notes

- HS256 only — the secret is symmetric, so verifiers must hold the same secret.
  Use the OIDC-provider stack (`asymjwt`) when third parties must verify tokens
  via a public JWKS.
- Refresh tokens are opaque, stored hashed, and rotate as a family with
  reuse-revocation (a replayed refresh token kills the family).
- **YAML:** `NewFromConfig` wires bearer from the `plugins.bearer` section;
  `jwt_secret_env` names the env var holding the HS256 secret (it also seeds the
  host `WithJWTSecret`). `NewFromConfig` errors if that env var is empty.
