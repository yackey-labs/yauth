# passkey — WebAuthn / passkeys (TouchID, FaceID, security keys)

The `passkey` plugin adds WebAuthn credentials as a login method: platform
authenticators (TouchID/FaceID/Windows Hello) and roaming security keys.
Enrollment is auth-gated (an existing session registers a passkey); login
supports both the email-hinted flow and the discoverable (empty-body) flow
where the platform picks the credential.

## Endpoints (under your mount prefix)

| Method | Path                       | Purpose                                                  |
| ------ | -------------------------- | -------------------------------------------------------- |
| POST   | `/passkeys/register/begin` | start registration; returns `{challenge_id, options}` (auth-gated) |
| POST   | `/passkeys/register/finish`| verify attestation, store the credential (auth-gated)    |
| POST   | `/passkey/login/begin`     | start an assertion; empty body = discoverable flow       |
| POST   | `/passkey/login/finish`    | verify assertion, issue a session cookie (or a step-up challenge) |
| GET    | `/passkeys`                | list the caller's passkeys (auth-gated)                  |
| DELETE | `/passkeys/{id}`           | delete one of the caller's passkeys (auth-gated)         |

Both `begin` endpoints return `{challenge_id, options}` — the `options` member
wraps the standard `publicKey` credential options the browser API consumes, and
the matching `finish` call **requires** the `challenge_id` plus the browser's
credential response. Migrations create `yauth_webauthn_credentials`.

## A passkey satisfies MFA (default)

When the `mfa` plugin is also wired, a TOTP-enrolled user finishing a passkey
login is **not** asked for a code. `/passkey/login/finish` reports the login as
already second-factor-verified and issues the session in one leg. This is a
deliberate default:

- a passkey assertion is not a single factor — it is possession of the
  authenticator plus, with user verification, a biometric or PIN. NIST
  SP 800-63B rates a verified WebAuthn authenticator at AAL2/AAL3, and Entra,
  Okta and Google all accept a passkey on its own;
- it is phishing-resistant. Chasing it with a shared-secret TOTP adds the
  weaker factor's failure modes (relay, real-time phishing, seed theft) to a
  flow that had none;
- it is what this route has always done, so no existing passkey user's login
  changes shape.

**To demand a step-up anyway**, set `satisfies_mfa: false`
(`passkey.Config.SatisfiesMFA` = pointer to `false`). `/passkey/login/finish`
then answers `{require_mfa, pending_session_id}` with **no** `Set-Cookie`, and
the login completes at `POST /mfa/verify` — the same second leg the cookie
password login uses. Note this **changes behaviour for existing passkey users
who have TOTP enrolled**: they will be prompted for a code they were never
asked for before, so ship the client-side handling of `require_mfa` first.

Independent of the flag, a `Block` decision — `lockout`, an IP-deny handler —
is **always** honoured: `/passkey/login/finish` refuses with the handler's
status and issues no session. A locked account cannot get in with its passkey.

## YAML (`NewFromConfig`)

```yaml
plugins:
  passkey:
    enabled: true
    rp_id: example.com               # effective domain — no scheme, no port
    rp_name: My App                  # shown in the platform prompt
    rp_origin: https://app.example.com  # EXACT browser origin (scheme://host[:port])
    # satisfies_mfa: false           # optional; default true (see above)
```

The three RP fields are required. `rp_origin` must match the origin the browser
reports in `clientDataJSON` exactly — for a Vite/SPA dev setup that proxies
`/api`, that is the **dev server's** origin (e.g. `http://localhost:5173`), not
the backend's.

## Builder API

```go
pk, err := passkey.New(passkey.Config{
    RPID:      "example.com",
    RPName:    "My App",
    RPOrigins: []string{"https://app.example.com"}, // builder accepts several; yaml maps rp_origin → one
})
// ... handle err ...
ya, err := yauth.New(repo, yauth.NewDefaultConfig()).WithPlugin(pk).Build()
```

## TypeScript / Vue

`@yackey-labs/yauth-client` exposes the flows under `client.passkey`
(`registerBegin/registerFinish`, `loginBegin/loginFinish`, `list`, `delete`);
`@yackey-labs/yauth-ui-vue` builds on it:

- `<LoginForm show-passkey />` — adds a "Sign in with passkey" button under the
  password form.
- `<PasskeyButton mode="login" />` / `<PasskeyButton mode="register" />` — the
  standalone button (register mode needs an authenticated session).
- `<ProfileSettings />` — lists and deletes the caller's passkeys (pair it with
  a register-mode `PasskeyButton` for enrollment).

Hand-rolled flows must thread `challenge_id` from each `begin` response into
the matching `finish` request and pass `options.publicKey` to
`@simplewebauthn/browser`'s `startRegistration`/`startAuthentication`.

## Notes

- Registration requires a logged-in session — passkeys are an additional
  credential on an existing account, not a sign-up path.
- `rp_id` scopes credentials: keys minted for `example.com` work on subdomains,
  but changing `rp_id` later strands previously registered credentials.
- An https origin is required by browsers everywhere except `localhost`.
- The client SDK always exposes `client.passkey`; gate UI on your own knowledge
  of the server config if the plugin may be disabled (calls 404 otherwise).
