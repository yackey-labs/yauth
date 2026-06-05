# Mounting yauth in your app

This is the canonical guide to wiring a built `*YAuth` onto your HTTP server.

## What yauth gives you, and what stays yours

yauth provides the **API** (endpoints under a path prefix) and the **components**
(URLs + JSON your frontend calls, plus the OIDC/OAuth discovery documents). Your
SPA owns the **pages** — login, register, consent, account screens. yauth never
serves HTML; the `@yackey-labs/yauth-ui-vue` / `-solidjs` components render the UI
against yauth's API.

## The default layout: `y.Mount`

Mount the API under `/api/auth` — the ecosystem default. The Vue/SolidJS
components' `baseUrl` defaults to `/api/auth` (`authBaseUrl ?? "/api/auth"`), so
matching it means zero frontend config.

`y.Mount(mux, MountOptions{})` gives you the turnkey single-tenant-IdP layout:

- the API under `/api/auth/` (with a `/api/auth` → `/api/auth/` redirect), and
- OIDC/OAuth discovery + JWKS **also aliased at the host root** —
  `/.well-known/openid-configuration`, `/.well-known/oauth-authorization-server`,
  `/.well-known/jwks.json` — in addition to under the prefix.

```go
package main

import (
	"net/http"

	yauth "github.com/yackey-labs/yauth"
	"github.com/yackey-labs/yauth/plugins/asymjwt"
	"github.com/yackey-labs/yauth/plugins/oauth2server"
	"github.com/yackey-labs/yauth/plugins/oidc"
	"github.com/yackey-labs/yauth/repo/memrepo"
)

func main() {
	asym, _ := asymjwt.New(asymjwt.Config{
		KeyType: "RS256", PrivateKeyPath: "private.pem", PublicKeyPath: "public.pem", KID: "k1",
	})

	y, _ := yauth.New(memrepo.New(), yauth.NewDefaultConfig()).
		WithPlugin(asym).
		WithPlugin(oauth2server.New(oauth2server.Config{
			Issuer:   "https://idp.example.com", // bare origin — see "Issuer is identity"
			BasePath: "/api/auth",               // == APIPrefix
		})).
		WithPlugin(oidc.New(oidc.Config{
			Issuer:   "https://idp.example.com",
			BasePath: "/api/auth",
		})).
		Build()

	mux := http.NewServeMux()
	y.Mount(mux, yauth.MountOptions{}) // API under /api/auth + discovery at root
	_ = http.ListenAndServe(":3000", mux)
}
```

The low-level `y.Router()` is still there for advanced/custom mounting (e.g. the
classic `mux.Handle("/api/auth/", http.StripPrefix("/api/auth", y.Router()))`).
`Mount` is additive ergonomics over it, not a replacement.

## Issuer is identity — set it to the bare origin

This is the one rule you can break in a way that silently breaks strict OIDC
relying parties: **the `issuer` must equal the origin an RP fetched discovery
from.** Root discovery (the default) is therefore only valid when the issuer is
the **bare origin**:

```
Issuer:   https://idp.example.com   # scheme + host, no path
BasePath: /api/auth                 # where the endpoints live
```

The discovery doc then reports `issuer = https://idp.example.com` — matching
`https://idp.example.com/.well-known/openid-configuration` at the root — while
`authorization_endpoint` / `token_endpoint` / `jwks_uri` point under
`https://idp.example.com/api/auth/…`. An issuer that differs from the endpoint
base is **valid OIDC**, and it is exactly what the big providers do.

**Never make the issuer your API mount path.** Path-carried issuers
(`https://host/realms/{realm}`) are a **multi-tenant** convention — one issuer
per tenant — not the single-tenant pattern this default targets.

### Who does what

| Provider          | Issuer (identity)              | Endpoint base                | Discovery |
| ----------------- | ------------------------------ | ---------------------------- | --------- |
| Okta org server   | `https://org.okta.com` (root)  | `…/oauth2/v1/…`              | root      |
| Auth0 / Google    | root origin                    | root origin                  | root      |
| Keycloak          | `…/realms/{realm}` (per realm) | `…/realms/{realm}/protocol/…`| per realm |
| **yauth default** | bare origin                    | `…/api/auth/…`               | root      |

yauth's default mirrors Okta's org server: root issuer, root discovery,
path-prefixed endpoints.

## The `DiscoveryAtRoot` toggle

`MountOptions.DiscoveryAtRoot` is a `*bool`; `nil` means **true** (root discovery
on). Set it to an explicit `false` to keep discovery **only under the prefix** —
appropriate when the issuer carries a path and root discovery would be wrong:

```go
off := false
y.Mount(mux, yauth.MountOptions{DiscoveryAtRoot: &off})
```

`MountOptions.APIPrefix` overrides the `/api/auth` default (a trailing slash is
ignored). Setting it explicitly to `"/"` mounts the router at the root with no
prefix and no separate root alias (the root already covers `/.well-known/`).

## Related

- `yauth docs plugins/oidc-provider` — stand up the OIDC/OAuth provider stack
- `yauth docs configuration` — config paths, precedence, the shared issuer rule
- `yauth docs mcp` — MCP servers add RFC 9728 protected-resource metadata via
  `mcpauth.Mount` on top of this layout
- `yauth docs typescript/setup` — the frontend components and `baseUrl`
