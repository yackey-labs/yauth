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
  source that emits it (e.g. `emailpassword`). It's standalone otherwise.
- **YAML:** `NewFromConfig` wires mfa from the `plugins.mfa` section;
  `encryption_key_env` names the env var holding the base64-encoded 32-byte key
  (as emitted by `yauth gen-secrets`). `NewFromConfig` errors if it's missing or
  the wrong length.
