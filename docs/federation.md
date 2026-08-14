# SSO federation (yauth → yauth and OIDC)

Connect one yauth app (the **relying party**, RP) to another OIDC issuer (the
**OpenID Provider**, OP — e.g. a central yauth IdP) so users sign in across apps.
Both halves are yauth plugins:

- **RP side:** `plugins/ssooidc` — inbound "Sign in with <IdP>". Mounts
  `/sso/login`, `/sso/callback`, global admin `/sso/connections`, and org-scoped
  admin `/organizations/{id}/sso/connections` (+ `/sso/federate`) under
  `/api/auth`. Wire it declaratively with `plugins.sso_oidc` (below) or via the
  builder.
- **OP side:** `plugins/oauth2server` (+ `oidc`, `asymjwt`) — the issuer the RP
  federates to. Dynamic client registration (DCR) lets RPs self-register.

Runnable end-to-end reference: **`examples/sso/`** (`./examples/sso/demo.sh`).

## Which shape? (decide this first)

Two independent choices: the **scope** of the connection (who it routes), and
the **onboarding path** (how the RP gets registered at the OP).

**Connection scope — ask "whose IdP is it?"**

| Scope | Use when | Login routing |
| ----- | -------- | ------------- |
| **Global** (`/sso/connections`) | The IdP belongs to *you* and serves everyone — workforce SSO against your central IdP, or "Sign in with Google" on any app. Single-tenant apps; orgs not required. | Render buttons from public `/sso/login-options`; drive with `?connection_id=` — or with no selector at all when exactly one global is active |
| **Org-scoped** (`/organizations/{id}/sso/connections`) | The IdP belongs to *your customer* — multi-tenant B2B where each org brings its own IdP (the WorkOS model). | Home-realm discovery: `?org=<slug>` or `?domain=<email-domain>` |

Mixing is fine: a B2B app can offer global "Sign in with Google" alongside
per-org enterprise connections. Differences on callback: an org-scoped login
JIT-stamps org membership + active org; a global login just links/creates the
user.

**Onboarding path — ask "who operates the OP, and do they pre-trust you?"**

| Path | Use when |
| ---- | -------- |
| Keyless trusted-issuer (`dcr_trusted_issuers`) | Both sides yauth and you operate both — internal platform apps against your own IdP. Zero secrets. |
| One-click runtime federate (`POST .../sso/federate`) | Same trust shape, but you want an admin button instead of code/seed. |
| Guided approval handshake (`/sso/federate/start` → `/federate/approve`) | Both sides yauth but the OP admin should approve each RP by hand — partner apps, no standing allow-list. |
| Manual / `SeedConnection` | The OP is a third party (Google, Okta, Entra): no DCR — paste the client_id/secret they issued. |

**Putting users in orgs** (org-scoped setups only) — three ways in, by who
drives: **invitation** (`POST .../invitations` + accept) when the *user*
consents — inviting outsiders in B2B; **direct add**
(`POST .../members`, idempotent) when an *admin* drives — workforce installs
and realm-flat consoles enrolling already-registered users; **SCIM** when the
*upstream directory* drives — provisioning from Okta/Entra.

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
`AllowAdminMachineCallers`). That key must be **user-scoped** and owned by an
admin — an org-scoped key never passes `RequireAdmin`, whatever
`AllowAdminMachineCallers` says, because its authority is the org and role
stamped on the key rather than its creator's global role.

### Guided approval handshake (any IdP, human-approved, no pre-trust)

When the OP shouldn't pre-trust the RP's issuer, use the browser-bounce handshake
— the OP admin approves each federation live (WorkOS-Admin-Portal style), no
allow-list edit:

1. RP admin → `GET {prefix}/sso/federate/start?idp=<OP base>&org=<id>&app_name=…`
   (org-admin gated). **`org` is optional**: omit it (install-admin gated
   instead) to seed a GLOBAL connection — the org-less default for
   single-tenant apps; the registered `initiate_login_uri` then selects by a
   pre-minted `connection_id` instead of an org slug. The RP signs a
   `federation_request` (its metadata +
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

The plugin itself is config-wireable — no Go code on the app side
(`NewFromConfig` / yauth.yaml):

```yaml
plugins:
  sso_oidc:
    enabled: true
    encryption_key_env: SSO_ENCRYPTION_KEY # base64 32-byte AES key (`yauth gen-secrets`)
    # state_ttl: 10m                       # /sso/login → /sso/callback window
    # allowed_redirect_urls: ["/dashboard"] # empty = redirect_url ignored
    # self_issuer: https://app/api/auth    # enables the keyless runtime federate endpoint
    # allow_private_network_idp: true     # ONLY for an in-cluster IdP — see below
```

**`allow_private_network_idp` (default `false`).** A connection's
`discovery_url` is chosen by an org admin and the server then dials it — on
`/test`, on every `/sso/login` and `/sso/callback`, and on back-channel logout
— so by default those fetches refuse loopback and RFC 1918 destinations. If
your IdP lives inside the perimeter (`http://keycloak.identity.svc:8080`,
`http://127.0.0.1:8081` in the examples), set this to `true` or every SSO login
fails with a 502. `169.254.0.0/16` (the cloud instance-metadata service) stays
refused either way.

Drive one with `GET {prefix}/sso/login?connection_id=<id>&redirect_url=/path` —
or, when exactly ONE global connection is active (the common single-IdP shape),
plain `GET {prefix}/sso/login?redirect_url=/path` resolves it with no selector
(two+ active globals make that ambiguous → 400, pass connection_id).
On callback a global connection **just links/creates the user** — no org
membership, no active-org stamp. A login page renders "Sign in with X" buttons
from `/sso/login-options` (public, ids + names only). Adding Google is then: a
global connection with `discovery_url = https://accounts.google.com/.well-known/openid-configuration`
+ a client_id/secret from Google Cloud Console (Google isn't keyless — that path
is yauth↔yauth only). Orgs remain available for multi-tenant/B2B; they're now
optional, not required.

Apps that DO keep one hidden org (for org-scoped groups/SCIM under a
single-tenant UI) can enroll users into it directly —
`POST {prefix}/organizations/{id}/members` `{user_id, role?}` (org-admin or
install-admin gated, idempotent) — no invitation round-trip.

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
6. **Org-scoped connections need the user in the org.** If you use the
   org-scoped shape in a single-tenant app (e.g. for org-scoped groups/SCIM),
   the anchor org is plumbing — don't let it become the data tenant, and enroll
   users via `POST /organizations/{id}/members` (or SCIM), not by hand. If you
   don't need orgs at all, use a global connection instead.
7. **Connection `redirect_url`** (the post-login landing) must be the param the
   RP reads (`redirect_url`) and either a relative `/path` or an entry in
   `ssooidc.Config.AllowedRedirectURLs`.
8. **The IdP owns MFA on the RP side.** An SSO login declares the upstream
   IdP's authentication to be the second factor, so a user with local TOTP
   enrolled is not stepped up (`sso_oidc.satisfies_mfa`, default `true`; same
   for `oauth` and ssosaml). The callback is a browser redirect with nowhere
   to put a `{require_mfa, pending_session_id}` challenge, so setting it
   `false` does not produce a step-up — it refuses the login with 403. A
   `Block` from `lockout` is honoured regardless: a locked account gets no
   session through SSO either.

## Login-state browser binding (`login_state_binding`)

A federated login is started in one browser and finished in another HTTP
request. Historically nothing tied the two together: `/authorize` (oauth) and
`/sso/login` (sso_oidc) minted a random `state`, wrote a **server-side** row and
redirected to the IdP without writing anything to the browser, and the callback
issued a session cookie to whichever browser turned up with a valid
`(code, state)` pair.

That made a finished-but-undelivered callback URL a portable credential. An
attacker starts a login in their own browser, authenticates at the IdP **as
themselves**, stops at `…/callback?code=…&state=…` and sends that URL to a
victim (a link, an `<img>`, an auto-submitting form aimed at the POST twin).
The victim's browser is then handed a session cookie for the *attacker's*
account — login CSRF / session fixation, RFC 9700 §4.1. Because yauth is itself
an IdP, every downstream relying party then signs the victim in as the attacker,
and any passkey or TOTP the victim goes on to enrol is enrolled on the
attacker's account. PKCE does not help here: the code, the state row and the
verifier are all consistently the attacker's, so the S256 check passes as
designed.

**The fix.** `/authorize` and `/sso/login` now put a random secret in a cookie
and derive the public state from it — `state = "b." || base64url(sha256(secret))`.
The callback reads the cookie named for that state and refuses with `400` if it
is missing or does not match. Nothing extra is stored: no column, no migration.
The check runs *before* the state row is consumed, so a refused delivery does
not burn the row belonging to the browser whose flow it is.

```yaml
plugins:
  oauth:
    login_state_binding: auto      # auto (default) | required | off
  sso_oidc:
    login_state_binding: auto
```

- **`auto`** (default) binds **iff `session.cookie_secure` is true**. Every TLS
  deployment is protected without touching yaml.
- **`required`** binds regardless — for a deployment that terminates TLS at a
  proxy and still wants the binding.
- **`off`** disables it.

### Why the binding cookie is `SameSite=None; Secure`

An IdP using `response_mode=form_post` returns by making the browser POST
**cross-site** to the callback, and a `SameSite=Lax` cookie is not sent on a
cross-site POST. The binding cookie therefore has to be `SameSite=None`, which
browsers only honour together with `Secure`. That is the whole reason `auto`
keys on `cookie_secure`: on plain HTTP the cookie could only be `Lax`, so
enforcing the binding would refuse every `form_post` login instead of protecting
anyone. **Plain HTTP is not covered under `auto`** — that is a deliberate,
documented fallback, not an oversight.

`SameSite=None` is safe *here specifically*: the cookie authorises nothing. It
only proves the flow started in this browser, and the state it unlocks is
single-use and server-side. It is `HttpOnly`, its name is derived from the
state (so two tabs / two providers do not clobber each other), it expires with
the state TTL, and it is cleared on every callback exit — success and refusal
alike.

### Flows this deliberately breaks

1. **Cross-device / cross-browser continuation.** Start the login on the
   desktop, finish the IdP leg on a phone, or paste the callback URL into a
   different browser. Refused — and that *is* the attack, so it is intended. If
   your users have been trained to do it, lead the release note with this.
2. **A native / mobile client that fetches `/authorize` with its own HTTP client
   and then opens the returned URL in an external browser.** The two jars are
   different, so the callback lands in a browser that never received the cookie
   and is refused. Such deployments need `login_state_binding: off`. First-party
   webviews and `ASWebAuthenticationSession` are fine — start and finish share a
   jar.
3. **An SPA on a different registrable domain from yauth** is unaffected for
   *login* (`/authorize` is a top-level navigation and the callback is a
   top-level cross-site navigation, where `SameSite=None` cookies are still
   delivered). Note that `POST /oauth/{provider}/link` is deliberately **not**
   bound: link mode never issues a session, so there is no fixation to close,
   and its state row can only ever reach the link path.
4. **Safari older than 13** mishandles `SameSite=None` (treats it as Strict).
   Ancient, but worth knowing if you support it.

`ssosaml`'s ACS + `RelayState` has the same shape and is **not** covered yet;
the binding is prefix-driven, so those flows are simply unaffected either way.

The `400` body names the knob verbatim, so an operator reading a support ticket
learns the escape hatch from the response itself.

## IdP launcher

`oauth2server` clients with an `initiate_login_uri` (the RP's SP-initiated login
URL) appear as launchable tiles; `Federate` sets it automatically. A federated
(DCR) client surfaces in a launcher only when it carries that launch URL.

## Tracing

The ssooidc discovery/JWKS/token client, the `Federate` DCR client, and the OP's
trusted-issuer JWKS client all use `otelhttp`, so the W3C `traceparent`
propagates — an SSO login is one distributed trace across RP + OP.
