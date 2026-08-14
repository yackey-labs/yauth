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

**Precondition (since the consent gate).** Direct enrolment writes an ACTIVE
membership the target never agreed to, so unless the caller is an *install-wide*
admin (`user.role == "admin"`, which a realm-flat console usually is — that path
is unchanged) the org must hold a **verified domain** covering the target's email
address, else `403`. Three ways to satisfy it, cheapest first:

- verify the org's email domain (`POST /organizations/{id}/domains` then
  `.../verify`) — the same proof SCIM adoption and domain auto-join already use;
- invite instead: `POST /organizations/{id}/invitations`, which the user accepts
  (and which you can now list and revoke, see below);
- or, for a console that drives the API as an org **owner** while holding the
  global role `"user"`, set `plugins.organizations.allow_direct_member_enrollment:
  true`. That restores the old behaviour wholesale, including the fact that an
  org admin can then place any user in any group — and group names ride into the
  `groups` claim of that user's id_token at every relying party. Only turn it on
  where org-admin is already an operator-level trust boundary.

Pending invitations are manageable: `GET /organizations/{id}/invitations` lists
them (admin-gated, never returns the token) and
`DELETE /organizations/{id}/invitations/{invitation_id}` revokes one before its
TTL expires.

**Reviewing memberships that predate the gate.** Rows already in the database
were written under the old rule, so upgrading does not undo them. This query
lists memberships with no accepted invitation and no verified domain behind
them — it is a **review list, not a delete list**:

```sql
SELECT m.organization_id, m.user_id, m.role, m.created_at
  FROM yauth_memberships m
  JOIN yauth_users u ON u.id = m.user_id
  LEFT JOIN yauth_invitations i
    ON i.organization_id = m.organization_id
   AND lower(i.email) = lower(u.email)
   AND i.accepted_at IS NOT NULL
  LEFT JOIN yauth_organization_domains d
    ON d.organization_id = m.organization_id
   AND d.status = 'verified'
   AND d.domain_canonical = lower(split_part(u.email, '@', 2))
 WHERE i.id IS NULL AND d.id IS NULL AND m.invited_at IS NULL;
```

Two large classes of **false positive** show up here and are perfectly
legitimate: SCIM-provisioned members (plugins/scim writes an active membership
directly, with no invitation row) and domain auto-join members (keyed on a
verified domain at signup time, but they leave `invited_at` NULL and the domain
row may since have been removed or re-verified elsewhere). Read the list, don't
pipe it into a DELETE.

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
   don't need orgs at all, use a global connection instead. Note the enrolment
   route's consent gate (above): an install-wide admin caller is exempt, but an
   org-owner caller with the global role `"user"` needs the org's email domain
   verified, an invitation, or
   `plugins.organizations.allow_direct_member_enrollment: true`.
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

## IdP launcher

`oauth2server` clients with an `initiate_login_uri` (the RP's SP-initiated login
URL) appear as launchable tiles; `Federate` sets it automatically. A federated
(DCR) client surfaces in a launcher only when it carries that launch URL.

## Tracing

The ssooidc discovery/JWKS/token client, the `Federate` DCR client, and the OP's
trusted-issuer JWKS client all use `otelhttp`, so the W3C `traceparent`
propagates — an SSO login is one distributed trace across RP + OP.
