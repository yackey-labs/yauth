# bearer — JWT access + refresh tokens

The `bearer` plugin issues HS256 JWT access tokens plus opaque refresh tokens
for API/mobile clients that authenticate with `Authorization: Bearer <token>`
instead of a session cookie. (For RS256/ES256 tokens an OIDC RP can verify via
JWKS, that's the OIDC-provider path — see `yauth docs plugins/oidc-provider`.)

## Endpoints (under your mount prefix)

| Method | Path             | Purpose                                        |
| ------ | ---------------- | ---------------------------------------------- |
| POST   | `/token`         | email + password → `{access_token, refresh_token}` |
| POST   | `/token/refresh` | rotate the refresh token (family rotation, reuse-revocation) |
| POST   | `/token/revoke`  | revoke a refresh-token family (auth-gated)     |

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
