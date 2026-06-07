# SSO federation (yauth → yauth and OIDC)

Connect one yauth app (the **relying party**, RP) to another OIDC issuer (the
**OpenID Provider**, OP — e.g. a central yauth IdP) so users sign in across apps.
Both halves are yauth plugins:

- **RP side:** `plugins/ssooidc` — inbound "Sign in with <IdP>". Mounts
  `/sso/login`, `/sso/callback`, and org-scoped admin
  `/organizations/{id}/sso/connections` (+ `/sso/federate`) under `/api/auth`.
- **OP side:** `plugins/oauth2server` (+ `oidc`, `asymjwt`) — the issuer the RP
  federates to. Dynamic client registration (DCR) lets RPs self-register.

Runnable end-to-end reference: **`examples/sso/`** (`./examples/sso/demo.sh`).

## Easiest: keyless trusted-issuer federation (no secret, no copy-paste)

Because both apps are yauth, the RP is also an issuer (it publishes a JWKS). The
RP signs a short-lived **`software_statement`** (RFC 7591) with its own key; the
OP — configured to **trust the RP's issuer** — verifies it against the RP's JWKS
and self-registers a confidential client. No admin key, no client secret pasted.
More automated than the manual paste (WorkOS) or registration-token (Ory) flows.

```go
// OP (the IdP): trust the RP's issuer.
oauth2server.Config{ DCRTrustedIssuers: []string{"https://app/api/auth"},
                     DCREnabled: true }
// config-driven (NewFromConfig / yauth.yaml):  oauth2_server.dcr_trusted_issuers: ["https://app/api/auth"]

// RP (the app): one idempotent call. Needs asymjwt (RS256) + an OIDC discovery
// so the OP can fetch the RP's JWKS; the RP must be serving before it federates.
ssooidc.Federate(ctx, repo, encKey, ssooidc.FederateInput{
    DiscoveryURL:      "https://idp/.well-known/openid-configuration",
    SoftwareStatement: stmt,                 // ssooidc.SignSoftwareStatement(signer, issuer, redirectURIs, appName, scope, ttl)
    OrganizationID:    anchorOrgID,
    ConnectionName:    "tiny-idp",            // local name (the IdP)
    ClientName:        "My App",              // our name in the IdP's launcher
    InitiateLoginURI:  "https://app/api/auth/sso/login?org=<slug>&redirect_url=/dashboard",
    RedirectURI:       "https://app/api/auth/sso/callback",
    JitProvisioningEnabled: true, DefaultRoleOnJit: "viewer",
    GroupToRole: map[string]string{"platform-admins": "owner"},
})
```

### One-click runtime federation (admin button)

`ssooidc` also serves `POST {prefix}/organizations/{id}/sso/federate` (org-admin
gated). The admin supplies the IdP's `discovery_url` (+ optional `app_name`,
`launch_redirect`); the app signs the statement server-side (via
`Config.SelfIssuer` + the registered asymjwt signer), auto-builds
`initiate_login_uri` from the org slug, federates, and returns the connection.
Back it with a button that POSTs to it. When the OP doesn't trust the issuer,
pass `admin_api_key` instead (needs OP `DCRAllowConfidentialClients` +
`AllowAdminMachineCallers`).

### Guided approval handshake (any IdP, human-approved, no pre-trust)

When the OP shouldn't pre-trust the RP's issuer, use the browser-bounce handshake
— the OP admin approves each federation live (WorkOS-Admin-Portal style), no
allow-list edit:

1. RP admin → `GET {prefix}/sso/federate/start?idp=<OP base>&org=<id>&app_name=…`
   (org-admin gated): the RP signs a `federation_request` (its metadata +
   `return_uri` + connection params, signed with its key) and **302s to the OP's
   `/federate/approve?req=<jwt>`** approval page.
2. OP approval page → `POST {prefix}/federate/review` (admin) shows the request →
   admin approves → `POST {prefix}/federate/approve` (admin) verifies the request
   against the RP's JWKS, registers a confidential client, mints a **one-time,
   short-TTL grant**, and returns `redirect_url` back to the RP's `return_uri`.
3. RP `GET {prefix}/sso/federate/return` verifies the echoed request (its own
   signature), **redeems the grant server-to-server** (`POST {prefix}/federate/redeem`)
   for the client creds, and seeds the connection. The secret never enters a
   browser; the grant is single-use.

The OP needs `DCREnabled` + an `/federate/approve` UI page (yauth-ui has none —
tiny-idp ships `FederateApproveView`); the RP needs `Config.SelfIssuer` + an
asymjwt signer. The grant store is in-process (single-replica IdP; a restart
mid-handshake just means re-approve).

### Org-less (global) connections — for apps without organizations

Single-tenant apps that don't model orgs (and "Sign in with Google/Okta" on any
app) use **global** connections — `organization_id` is the empty sentinel `""`
(no migration, no FK). Manage them with the **global-admin-gated** CRUD
(distinct from the org-scoped routes):

```
POST   {prefix}/sso/connections          create a global connection (admin)
GET    {prefix}/sso/connections          list global connections (admin)
PATCH  {prefix}/sso/connections/{cid}    update (admin)
DELETE {prefix}/sso/connections/{cid}    delete (admin)
POST   {prefix}/sso/connections/{cid}/test
GET    {prefix}/sso/login-options         PUBLIC: [{id,name}] of ACTIVE globals
```

Drive one with `GET {prefix}/sso/login?connection_id=<id>&redirect_url=/path`.
On callback a global connection **just links/creates the user** — no org
membership, no active-org stamp. A login page renders "Sign in with X" buttons
from `/sso/login-options` (public, ids + names only). Adding Google is then: a
global connection with `discovery_url = https://accounts.google.com/.well-known/openid-configuration`
+ a client_id/secret from Google Cloud Console (Google isn't keyless — that path
is yauth↔yauth only). Orgs remain available for multi-tenant/B2B; they're now
optional, not required.

### Lower-level

- `ssooidc.SeedConnection(ctx, repo, key, in)` — connection-as-code when you
  already have the IdP's `client_id` + `client_secret` (encrypts the secret at
  rest; no UI, no DCR).
- The `SsoConnectionForm`/`SsoConnectionList` (yauth-ui-vue) admin components.

## Sharp edges (each one will cost you a round-trip otherwise)

1. **RP must set `cfg.BaseURL`** to its public origin — ssooidc builds the OAuth
   `redirect_uri` (and the federate callback) from it; unset → a relative
   `redirect_uri` → the OP rejects it ("redirect_uri is not registered").
2. **`Issuer` already includes `/api/auth`** → set `oauth2server`/`oidc`
   `BasePath: ""`, else discovery doubles the path (`/api/auth/api/auth/...`) →
   token/JWKS 404.
3. **The OP must sign id_tokens asymmetrically** (`asymjwt`, RS256) + publish a
   JWKS — `bearer`/HS256 alone has no `jwks_uri` → the RP can't verify the
   id_token ("jwks endpoint 404"). The keyless RP also needs asymjwt (to sign
   the software_statement) + must be reachable when it federates (the OP calls
   back to fetch the RP's JWKS).
4. **OIDC discovery's `authorization_endpoint` must be the consent page**, not the
   raw JSON `/oauth/authorize`. If you front the OP with `mcpauth.Mount`
   (≥ v0.36.1), it patches both `oauth-authorization-server` and
   `openid-configuration` to `ConsentPath`.
5. **JIT applies `default_role_on_jit` on every login** (it overwrites a static
   seeded role) — keep admins elevated via `group_to_role`. JIT never *demotes*
   an existing owner (it would otherwise 500 on the last-owner guard).
6. **SSO connections are org-scoped**; single-tenant apps seed one anchor org and
   enroll their admins as owner-members. The anchor org is plumbing — don't let
   it become the data tenant (scope app data by the fixed tenant in single mode,
   not the active org).
7. **Connection `redirect_url`** (the post-login landing) must be the param the
   RP reads (`redirect_url`) and either a relative `/path` or an entry in
   `ssooidc.Config.AllowedRedirectURLs`.

## IdP launcher

`oauth2server` clients with an `initiate_login_uri` (the RP's SP-initiated login
URL) appear as launchable tiles; `Federate` sets it automatically. A federated
(DCR) client surfaces in a launcher only when it carries that launch URL.

## Tracing

The ssooidc discovery/JWKS/token client, the `Federate` DCR client, and the OP's
trusted-issuer JWKS client all use `otelhttp`, so the W3C `traceparent`
propagates — an SSO login is one distributed trace across RP + OP.
