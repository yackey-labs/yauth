# mfa — TOTP two-factor + backup codes

The `mfa` plugin adds TOTP (authenticator-app) second-factor with recovery
backup codes. It hooks the login pipeline: when a user with verified TOTP logs
in, the login returns `{require_mfa, pending_session_id}` instead of a real
session, and the client completes login via `/mfa/verify`.

## Endpoints (under your mount prefix)

| Method | Path                          | Purpose                                             |
| ------ | ----------------------------- | --------------------------------------------------- |
| POST   | `/mfa/totp/setup`             | create an unverified TOTP secret + backup codes (auth-gated) |
| POST   | `/mfa/totp/confirm`           | verify a code and activate TOTP (auth-gated)        |
| DELETE | `/mfa/totp`                   | remove TOTP + backup codes (auth-gated)             |
| GET    | `/mfa/backup-codes`           | count remaining unused backup codes (auth-gated)    |
| POST   | `/mfa/backup-codes/regenerate`| replace backup codes (auth-gated)                   |
| POST   | `/mfa/verify`                 | consume a pending session → issue a real session    |

A native client that logs in through the `bearer` plugin's `/token` gets the
same `{require_mfa, pending_session_id}` body, but completes the challenge at
`/token/mfa` instead — `/mfa/verify` ends in a session cookie, which such a
client cannot carry. Both routes consume the same pending session; whichever
is used first spends it.

## Wiring (builder API)

```go
var encKey [32]byte                 // AES-256 key; load from a secret manager
copy(encKey[:], mustDecodeKey(os.Getenv("MFA_ENCRYPTION_KEY")))

mfaPlugin, err := mfa.New(mfa.Config{
    EncryptionKey: encKey,          // REQUIRED — 32 bytes; New errors on the zero value
    Issuer:        "My App",        // otpauth:// label shown in authenticator apps
})
// ... handle err ...

ya, err := yauth.New(repo, yauth.NewDefaultConfig()).
    WithPlugin(emailpassword.New(emailpassword.Config{})).  // emits login.succeeded
    WithPlugin(mfaPlugin).
    Build()
```

## Notes

- `mfa.New` returns `(plugin, error)` — it errors if `EncryptionKey` is the zero
  value. The key encrypts TOTP secrets at rest; **rotating or losing it makes
  existing TOTP secrets unrecoverable**, so manage it like any AES key.
  `yauth gen-secrets` emits a suitable random key.
- MFA works by intercepting the `login.succeeded` event, so it needs a login
  source that emits it (e.g. `emailpassword`, `bearer`). It's standalone
  otherwise.
- The step-up is registered as a pipeline **gate**, so it runs ahead of every
  `RegisterEventHandler` observer whatever order the plugins were registered
  in. That is what stops `lockout` clearing a user's failure counter for a
  login that is still waiting on its second factor.
- Completing a challenge — `/mfa/verify`, or bearer's `/token/mfa` — emits its
  own `login.succeeded` carrying `events.MetaMFAVerified`. The login has only
  actually completed at that point, so that is when `lockout` clears its
  counter and what audit/webhook consumers should read as a finished login.
  The marker is also the loop breaker: without it the gate would re-challenge
  its own completion forever. A handler that ignores the marker and demands a
  further step-up is failed closed (403) rather than looped.
- A wrong code emits `login.failed`, so `lockout` throttles MFA brute force.
  The plugin has **no rate limiter of its own**, and before this no event
  reached one either — a 6-digit code could be guessed without limit.
- The plugin also publishes a `plugin.MFAVerifier` on the host. That is how
  `bearer`'s `/token/mfa` completes a challenge without importing this package
  or holding the TOTP encryption key; drop the mfa plugin and that route fails
  closed.
- **YAML:** `NewFromConfig` wires mfa from the `plugins.mfa` section;
  `encryption_key_env` names the env var holding the base64-encoded 32-byte key
  (as emitted by `yauth gen-secrets`). `NewFromConfig` errors if it's missing or
  the wrong length.
