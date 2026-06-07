# yauth → yauth SSO (OIDC federation) example

A minimal, runnable demo of **one yauth app signing in through another** over
OIDC: an **IdP** (`./idp`) and a **relying party** (`./rp`), both backed by an
in-memory repo, plus a headless driver (`demo.sh`) that exercises the whole
login end-to-end. This is the reference for wiring a yauth app as an SSO relying
party (see also the `federate-app` skill).

## Run it

```bash
# headless: builds both, drives the full SSO login, asserts the linked session
./examples/sso/demo.sh

# or interactively (two shells), then open http://127.0.0.1:8080/login
go run ./examples/sso/idp
go run ./examples/sso/rp
```

The RP **federates keylessly** — easier than WorkOS (manual client_id/secret
paste) or Ory (registration token). Because both apps are yauth, the RP is also
an issuer: it signs a short-lived **`software_statement`** (RFC 7591) with its
own key and presents it to the IdP's DCR endpoint. The IdP — configured to trust
the RP's issuer — verifies it against the RP's published **JWKS**, then
self-registers a confidential client and returns the secret over TLS. **No admin
key, no shared secret, nothing copy-pasted.** A same-email user in both apps
makes the first login demonstrate **JIT link-by-email**; new IdP users are
JIT-provisioned at `default_role_on_jit`, with admins kept elevated via
`group_to_role`.

The easiest path, end to end:

```go
// IdP: trust the peer's issuer (one allow-list entry).
oauth2server.Config{ DCRTrustedIssuers: []string{"https://app/api/auth"}, DCRAllowConfidentialClients: true }

// RP startup — sign a statement with our own key, then one call, zero secrets:
stmt, _ := ssooidc.SignSoftwareStatement(signer, "https://app/api/auth",
    []string{"https://app/api/auth/sso/callback"}, "My App", "openid email profile groups", 5*time.Minute)
ssooidc.Federate(ctx, repo, encKey, ssooidc.FederateInput{
    DiscoveryURL:      "https://idp/.well-known/openid-configuration",
    SoftwareStatement: stmt,            // ← issuer trust; no admin key
    OrganizationID: orgID, ConnectionName: "tiny-idp",
    RedirectURI: "https://app/api/auth/sso/callback",
    JitProvisioningEnabled: true, DefaultRoleOnJit: "viewer",
    GroupToRole: map[string]string{"platform-admins": "owner"},
})
```

(`AdminAPIKey` is still supported for IdPs that don't trust the issuer;
`ssooidc.SeedConnection` is the lowest-level "I already have client_id/secret" path.)

## Architecture

```
browser ──"Sign in with the Demo IdP"──▶ RP /api/auth/sso/login?org=demo
        ◀── 302 ── IdP /authorize (consent page) ──▶ POST /oauth2/consent
        ── 302 code ──▶ RP /api/auth/sso/callback
                         RP ⇄ IdP  token exchange (client_secret_basic) + JWKS verify
                         RP JIT-links/creates the user ──▶ RP session cookie
```

- **IdP** = `emailpassword` + **`asymjwt` (RS256)** + `oauth2server` + `oidc`,
  with `mcpauth.Mount` publishing root discovery whose `authorization_endpoint`
  points at the consent page.
- **RP** = `emailpassword` + **`ssooidc`**, one anchor org, one seeded connection.

## Sharp edges this example encodes (so you don't rediscover them)

1. **The RP must set `cfg.BaseURL`** to its public origin. ssooidc builds the
   OAuth `redirect_uri` as `BaseURL + /api/auth/sso/callback`; unset → a relative
   redirect_uri → the IdP rejects it with *"redirect_uri is not registered"*.
2. **`Issuer` already includes `/api/auth`, so `BasePath` must be `""`** on
   `oauth2server`/`oidc`. Setting both doubles the path in discovery
   (`/api/auth/api/auth/oauth/token`) → token/JWKS 404.
3. **The IdP needs asymmetric signing (`asymjwt`, RS256) + a JWKS.** A relying
   party verifies the id_token via `jwks_uri`; `bearer`/HS256 alone publishes no
   JWKS → *"jwks endpoint returned 404"*.
4. **OIDC discovery's `authorization_endpoint` must be a consent *page*, not the
   JSON `/oauth/authorize` API.** `mcpauth.Mount` (≥ v0.36.1) patches both the
   `oauth-authorization-server` and `openid-configuration` docs to `ConsentPath`.
5. **JIT never demotes an owner.** `default_role_on_jit` is applied on every
   login; ssooidc keeps an existing owner's role instead of failing the login
   when the repo refuses to demote the last owner (`ErrOwnerProtected`).
6. **Passwords are checked against known breaches** — use a strong unique one.

## Files

- `shared/` — constants both halves agree on (addresses, dev client creds, keys).
- `idp/` — the OpenID Provider (with browser login + consent pages).
- `rp/` — the relying party (login page with the SSO button; connection seeded as code).
- `demo.sh` — headless end-to-end driver / smoke test.
