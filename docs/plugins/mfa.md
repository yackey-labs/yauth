# mfa — TOTP two-factor + backup codes

The `mfa` plugin adds TOTP (authenticator-app) second-factor with recovery
backup codes. It hooks the login pipeline: when a user with verified TOTP logs
in, the login returns `{require_mfa, pending_session_id}` instead of a real
session, and the client completes login via `/mfa/verify`.

## Endpoints (under your mount prefix)

| Method | Path                          | Purpose                                             |
| ------ | ----------------------------- | --------------------------------------------------- |
| POST   | `/mfa/totp/setup`             | issue a **candidate** TOTP secret + backup codes (auth-gated, step-up) |
| POST   | `/mfa/totp/confirm`           | verify a code and promote the candidate (auth-gated)|
| DELETE | `/mfa/totp`                   | remove TOTP + backup codes (auth-gated, step-up)    |
| GET    | `/mfa/backup-codes`           | count remaining unused backup codes (auth-gated)    |
| POST   | `/mfa/backup-codes/regenerate`| replace backup codes (auth-gated, step-up)          |
| POST   | `/mfa/verify`                 | consume a pending session → issue a real session    |

## Step-up on the management routes

The three routes marked **step-up** change *how the account authenticates*, so
authentication alone does not open them. A user who already has a verified
factor must present a current TOTP code — or an unused backup code — in the
`X-MFA-Code` request header:

```http
DELETE /mfa/totp
Authorization: Bearer <token>
X-MFA-Code: 123456
```

Without it the server answers `403` with `detail: "current mfa code required"`;
a wrong code answers `403 invalid mfa code` and is counted as a failed login.
A **first** enrolment needs no header: there is no factor to prove and none to
lose.

Guessing the header is throttled twice over. The three step-up routes share the
`rate_limit.mfa_verify` bucket with `/mfa/verify` and `/token/mfa` — one per-IP
budget across all five, so alternating between them does not buy extra guesses
— and once the accumulated failures have locked the account, the next wrong
code is answered with lockout's `429 Account locked` instead of the `403`. The
lock is consulted only after a code has failed, so a user who can still produce
a correct code may disable or rotate their factor even while a lock (someone
else's password spray, say) stands against them.

A header rather than a body field, so it works uniformly on `DELETE`, where
request bodies are widely dropped by proxies and client libraries.

The reasoning: a second factor that can be removed without presenting it is not
a second factor. Anything that can ride a session — a stolen cookie, an XSS
payload — could otherwise disable the very control that exists to survive a
compromised primary credential.

## Enrolment is non-destructive

`POST /mfa/totp/setup` issues a **candidate**. The account keeps its existing
secret and its existing backup codes until `POST /mfa/totp/confirm` accepts a
code for the new secret; only then is the old factor replaced. An abandoned or
failed enrolment therefore changes nothing.

The candidate lives in the challenge store for 10 minutes. Starting setup again
discards the previous candidate — never a confirmed factor.

## TOTP codes are single-use

RFC 6238 §5.2: a code is accepted at most once. The time step of an accepted
code is recorded on the secret, and that step and every earlier one are refused
afterwards — so a code phished or shoulder-surfed in flight is dead as soon as
the real login lands, instead of staying valid for the rest of its window and
the skew either side of it.

Two consequences worth knowing:

- The code that CONFIRMS an enrolment is spent by confirming, and cannot be
  reused to sign in during the same 30-second window.
- Existing secrets carry no counter until their first use after upgrading
  (migration `011` adds the column as `NULL`), so nobody is locked out.

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

## Which login methods step up

`mfa` gates every `login.succeeded`, but not every login method should end in
a TOTP prompt, and not every method can express one. Each login plugin
therefore declares whether the credential it just checked counts as the second
factor. The decision is now made explicitly in each plugin and asserted in the
event (`events.MetaMFAVerified`) — it used to be an accident of whether the
plugin read `Emit`'s return value at all, and a plugin that did not both
skipped MFA silently and ignored a `Block` from `lockout`.

| Login method             | Steps up by default? | Config                                | Where the challenge is answered |
| ------------------------ | -------------------- | ------------------------------------- | ------------------------------- |
| `emailpassword` `/login` | yes                  | —                                     | `/mfa/verify`                   |
| `bearer` `/token`        | yes                  | —                                     | `/token/mfa`                    |
| `magiclink` `/verify`    | yes                  | `magic_link.satisfies_mfa` (def false)| `/mfa/verify`                   |
| `passkey` login/finish   | **no**, if UV        | `passkey.satisfies_mfa` (def true)    | `/mfa/verify`, when enabled     |
| `oauth` callback         | **no**               | `oauth.satisfies_mfa` (def true)      | n/a — fails closed with 403     |
| `sso_oidc` callback      | **no**               | `sso_oidc.satisfies_mfa` (def true)   | n/a — fails closed with 403     |
| `ssosaml` ACS            | **no**               | `Config.SatisfiesMFA` (def true)      | n/a — fails closed with 403     |

- **magic link steps up.** A link proves control of an inbox and nothing more
  — the same class of evidence as a password, and usually the same channel as
  the password reset, so treating it as a second factor collapses both factors
  onto one mailbox.
- **a USER-VERIFIED passkey does not.** It is possession plus a biometric/PIN
  and is phishing-resistant. The credit is graded on the assertion's UV flag:
  an authenticator that answers UV=0 proved possession only, so a TOTP-enrolled
  user **is** stepped up. See [passkey.md](passkey.md) for the full argument and
  for what changes if you set `satisfies_mfa: false`.
- **the federated flows do not, and cannot be made to cheaply.** `oauth`,
  `sso_oidc` and `ssosaml` end in a browser redirect, which has no body to
  carry `{require_mfa, pending_session_id}` and no agreed redirect target for
  a challenge page. Their default (`satisfies_mfa: true`) says the upstream
  IdP's authentication IS the second factor — the usual reason an org buys SSO
  in the first place. Setting `satisfies_mfa: false` there does not produce a
  step-up; it **fails the login closed with a 403**, for deployments that would
  rather refuse than let a federated login skip local MFA.

`Block` is separate and unconditional: **every** login method above honours it
and issues no session, so a locked account cannot get in by any route.

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
