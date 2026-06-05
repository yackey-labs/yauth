# OIDC identity provider (oidc + oauth2_server + asym_jwt)

Turning yauth into an OpenID Connect provider / OAuth2 authorization server —
the setup behind "log in with us", SSO, and MCP servers — is **four plugins
working together**, wired with the Go builder API:

| Plugin          | Role in the IdP                                                                 |
| --------------- | ------------------------------------------------------------------------------ |
| `emailpassword` | the actual login (how a user authenticates before consenting)                   |
| `asymjwt`       | RS256/ES256 signing key + `/.well-known/jwks.json` so RPs can verify tokens     |
| `oauth2server`  | `/authorize`, `/oauth/token`, consent, introspection, revocation, device, DCR  |
| `oidc`          | `/.well-known/openid-configuration` discovery + `/userinfo`                     |

You can wire this stack two ways — both are fully supported:

- **`yauth.yaml` + `NewFromConfig`** — declarative; secrets/keys come from
  `*_env` fields. Best when you want config-as-data. (See the YAML example below.)
- **Builder API** — `yauth.New(...).WithPlugin(...)`; programmatic. Required when
  you also call `mcpauth.Mount`/`Guard` (MCP), since those are Go-only.

## Canonical, compile-tested examples

Copy from these — they are built in CI, so they never drift from the API:

- **`examples/oidc`** — `asymjwt` + `oidc` + `emailpassword` + `bearer`: discovery, JWKS, userinfo.
- **`examples/oauth2server`** — `oauth2server` + `emailpassword` + `bearer`: full authorize → consent → token → introspect → revoke walkthrough.

A full provider combines both:

> Casing: the Go builder takes the JWS-canonical **uppercase** `"RS256"`/`"ES256"`
> (it becomes the token `alg` header). In `yauth.yaml` the `key_type` field is
> case-insensitive (`rs256` or `RS256` both validate).

```go
asym, err := asymjwt.New(asymjwt.Config{
    KeyType:        "RS256",        // or "ES256"
    PrivateKeyPath: priv,           // PEM path; or PrivateKeyPEM []byte
    PublicKeyPath:  pub,
    KID:            "yauth-key-1",
})
// ... handle err ...

ya, err := yauth.New(repo, yauth.NewDefaultConfig()).
    WithJWTSecret(hs256Secret).                                  // HS256 fallback signer
    WithPlugin(emailpassword.New(emailpassword.Config{})).
    WithPlugin(bearer.New(bearer.Config{})).
    WithPlugin(asym).                                            // RS256/ES256 + JWKS
    WithPlugin(oauth2server.New(oauth2server.Config{
        Issuer:   "https://idp.example.com",                    // see "Issuer" below
        BasePath: "/api/auth",                                  // must match your mount
    })).
    WithPlugin(oidc.New(oidc.Config{
        Issuer:   "https://idp.example.com",
        BasePath: "/api/auth",
    })).
    Build()
```

### Same stack via `yauth.yaml`

`NewFromConfig` wires all of these. Secrets and keys are referenced by env var /
path so the file is safe to commit. `issuer`/`base_path` default to
`server.base_url`/`server.prefix` and are shared by `oidc` and `oauth2_server`
so their metadata can never disagree.

```yaml
server:
  base_url: https://idp.example.com   # the IdP issuer
  prefix: /api/auth
plugins:
  email_password: { enabled: true }
  bearer:
    enabled: true
    jwt_secret_env: JWT_SECRET        # HS256 secret (also seeds WithJWTSecret)
  asym_jwt:
    enabled: true
    key_type: rs256                   # case-insensitive in yaml
    private_key_path: /etc/yauth/keys/private.pem
    public_key_path: /etc/yauth/keys/public.pem
    key_id: yauth-key-1
  oidc:
    enabled: true
  oauth2_server:
    enabled: true
    dcr_enabled: true                 # anonymous loopback DCR for local MCP clients
```

```go
ya, err := yauth.NewFromConfig(ctx, cfg) // cfg from yauthcfg.Load("yauth.yaml")
```

## How the plugins depend on each other

These are real, code-level behaviors (not config rules) — get them wrong and the
IdP degrades silently rather than erroring:

- **`oidc` advertises the authorize/token/registration/end-session endpoints
  only when `oauth2server` is also loaded.** `oidc` alone serves *only*
  discovery + `/userinfo` — no login flow. For a real provider, load both.
- **`oidc`/`oauth2server` sign with `asymjwt` when present, else fall back to
  HS256.** Without `asymjwt`, the discovery doc advertises `HS256` and there is
  no JWKS — relying parties cannot verify tokens against a public key. **Load
  `asymjwt` for any provider RPs will validate tokens from.**
- **`oauth2server` needs a signing key from *somewhere*** — the `asymjwt` signer,
  or an HS256 secret via `WithJWTSecret(...)`. Token issuance, introspection, and
  DCR registration-access-tokens fail without one.
- **`private_key_jwt` client auth requires `asymjwt`** (it verifies against the
  client's JWKS using the asymmetric path).

## Mounting — `y.Mount`

Mount the built `*YAuth` with `y.Mount(mux, yauth.MountOptions{})`. The default
layout is the single-tenant-IdP norm: the API under `/api/auth` (the ecosystem
default the Vue/SolidJS components expect) **plus** the discovery documents
aliased at the host root. Set `Issuer` to the bare origin and `BasePath` to the
API prefix (here `/api/auth`) so the root discovery doc's `issuer` matches the
URL clients fetch it from. See `yauth docs mounting` for the full guide,
including the `DiscoveryAtRoot` toggle and the issuer-as-identity rule.

```go
mux := http.NewServeMux()
y.Mount(mux, yauth.MountOptions{}) // API under /api/auth + discovery at root
```

The low-level `y.Router()` (mount it yourself under any prefix via
`http.StripPrefix`) remains available for custom routing.

## The `.well-known` surface

With `asymjwt` + `oauth2server` + `oidc` mounted under `BasePath` (e.g.
`/api/auth`), and root discovery on by default via `y.Mount`:

| Path                                                  | RFC / spec        | Served by      |
| ----------------------------------------------------- | ----------------- | -------------- |
| `{BasePath}/.well-known/openid-configuration`         | OIDC Discovery    | `oidc`         |
| `{BasePath}/.well-known/oauth-authorization-server`   | RFC 8414          | `oauth2server` |
| `{BasePath}/.well-known/jwks.json`                    | JWK Set           | `asymjwt`      |
| `/.well-known/openid-configuration` (root alias)      | OIDC Discovery    | `oidc`         |
| `/.well-known/oauth-authorization-server` (root alias)| RFC 8414          | `oauth2server` |
| `/.well-known/jwks.json` (root alias)                 | JWK Set           | `asymjwt`      |

The root aliases are byte-identical to the prefixed docs (the documents are built
from `Issuer`/`BasePath`, not the request path). Disable them by setting
`MountOptions.DiscoveryAtRoot` to an explicit `false` when the issuer is not the
bare origin.

(For an MCP server you also expose RFC 9728 protected-resource metadata at the
*root* via `mcpauth.Mount` — see `yauth docs mcp`.)

## Issuer

`Issuer` is the literal `iss` claim and the origin used to build the absolute
URLs in the discovery documents: `base = Issuer + BasePath`. Set `Issuer` to the
**exact public origin clients reach** (scheme + host), e.g.
`https://idp.example.com`, with `BasePath: "/api/auth"`. If `Issuer` disagrees
with the host clients actually use, strict OAuth/OIDC clients reject the
metadata. Behind a proxy, set it to the external origin, not the internal one.

## Dynamic client registration (DCR, RFC 7591)

Off by default. Enable with `DCREnabled: true` on `oauth2server.Config`:

- With `DCREnabled: true`, **public loopback-only clients** (all `redirect_uris`
  are `localhost`/`127.0.0.1`/`::1`) may register **anonymously** — exactly what
  local MCP / native-app clients (e.g. Claude Code) need. Non-loopback or
  confidential registrations require an authenticated admin.
- `DCRRequireAdminForLoopback: true` — restore strict mode: every registration
  needs an admin.
- `DCRAllowConfidentialClients: true` — allow DCR to mint confidential clients
  (default is public/PKCE only).

Anonymous loopback registration is an unauthenticated POST — rate-limit it at
your edge. See `yauth docs mcp` for the full MCP + DCR walkthrough and
`docs/mcp/SECURITY.md` for the threat model.

## Consent UI

`oauth2server`'s `/authorize` returns a JSON consent *payload*, not a page. Render
it with:

- **SPA:** `OAuthConsentPage` / `ConsentScreen` from `@yackey-labs/yauth-ui-vue`
  (route them at your `ConsentPath`, e.g. `/authorize`). See `yauth docs typescript/setup`.
- **Non-SPA:** `mcpauth.HTMLConsentHandler` renders a server-side consent page.

## Related

- `yauth docs mcp` — stand up an MCP server (DCR + OIDC + protected-resource metadata)
- `yauth docs bearer` — the bearer/JWT plugin
- `yauth docs typescript/setup` — frontend wiring
