# Standing up an MCP server on yauth-go

This guide wires an [MCP](https://modelcontextprotocol.io) server so an MCP
client (Claude Code, Claude Desktop, …) can authenticate against a yauth-go
authorization server with the standard OAuth 2.1 + PKCE browser flow — no static
tokens, no per-client config. The [`mcpauth`](../../mcpauth) helper package does
the parts yauth can't do from a plugin, and the SPA `ConsentScreen` /
`OAuthConsentPage` components (shipped in `@yackey-labs/yauth-ui-solidjs` and
`@yackey-labs/yauth-ui-vue`) render the consent page.

> If you just want it working: jump to [Wiring](#wiring) and
> [Consent UI](#consent-ui). The rest explains *why* each line is there so the
> footguns stop biting.

## The one thing to understand

yauth registers **every** route at the root of its own mux with an empty prefix.
You mount that mux under a prefix yourself:

```go
mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))
```

So yauth's RFC 8414 metadata ends up at `/api/auth/.well-known/oauth-authorization-server`.
But the MCP authorization spec — and the OAuth clients that implement it — only
discover the authorization server from two documents that **must live at the
resource server root**:

| Document | Path (root) | Who emits it |
|---|---|---|
| Protected Resource Metadata (RFC 9728) | `/.well-known/oauth-protected-resource` | **nobody** — yauth has no such endpoint |
| Authorization Server Metadata (RFC 8414) | `/.well-known/oauth-authorization-server` | yauth, but under the mount prefix |

A yauth *plugin* can't fix this: a plugin only ever sees the mount prefix, never
the root mux. That is the root cause of every "little issue" people hit. The
`mcpauth` package mounts the missing root endpoints and proxies/patches yauth's.

## The footguns (and who handles each)

| # | Footgun | Symptom | Fix |
|---|---|---|---|
| 1 | No RFC 9728 metadata at root | Client can't find the AS; auth never starts | `mcpauth.Mount` serves `/.well-known/oauth-protected-resource` |
| 2 | RFC 8414 metadata is under `/api/auth`, not root | Client probes root, gets 404 | `mcpauth.Mount` aliases it to root (and the RFC 8414 §3.1 path-suffixed form) |
| 3 | `authorization_endpoint` points at yauth's JSON `/oauth/authorize` | Browser opens the consent step and sees raw JSON | `mcpauth.Mount` rewrites it to your SPA `ConsentPath` |
| 4 | 401 has no `WWW-Authenticate` and is `text/plain` | Client can't auto-discover; MCP client can't parse the error | `mcpauth.Guard` adds `WWW-Authenticate: Bearer resource_metadata="…"` and answers JSON |
| 5 | The consent step has no UI | yauth returns a JSON consent *payload*, not a page | SPA `OAuthConsentPage`/`ConsentScreen`, or `mcpauth.HTMLConsentHandler` for non-SPA servers |
| 6 | App routes not all under `/api`, `/mcp` has no trailing-slash route, SPA catch-all registered first | `/mcp/` returns your SPA's `index.html`; OAuth routes get swallowed | Register `/mcp` **and** `/mcp/`, keep the SPA catch-all **last** (see [Routing](#routing-checklist)) |
| 7 | MCP clients register dynamically (RFC 7591), anonymously | First connect fails: `401 initial access token required` (or "client not found") | Set `DCREnabled: true` **and** `DCRRequireInitialAccessToken: &openDCR` (`openDCR := false`) — `DCREnabled` alone still requires an admin token |
| 8 | `Issuer` ≠ the host clients actually use | Strict clients reject the metadata; `token_endpoint` points at the wrong host | Set oauth2server `Issuer` to the exact public origin (see [Issuer gotcha](#issuer-must-match-the-public-origin)) |

## Wiring

```go
import (
	"net/http"

	yauth "github.com/yackey-labs/yauth"
	"github.com/yackey-labs/yauth/mcpauth"
	"github.com/yackey-labs/yauth/plugins/bearer"
	"github.com/yackey-labs/yauth/plugins/emailpassword"
	"github.com/yackey-labs/yauth/plugins/oauth2server"
)

func newYAuth(repo /* repo.Repository */) (*yauth.YAuth, error) {
	// MCP clients register *anonymously* via DCR. DCREnabled alone is NOT
	// enough: DCRRequireInitialAccessToken defaults to true, so an anonymous
	// register returns `401 initial access token required`. Open it explicitly.
	openDCR := false
	return yauth.New(repo, yauth.NewDefaultConfig()).
		WithJWTSecret(secret).
		WithPlugin(emailpassword.New(emailpassword.Config{})).
		WithPlugin(bearer.New(bearer.Config{})). // resolves the access token on /mcp
		WithPlugin(oauth2server.New(oauth2server.Config{
			// Issuer MUST be the exact public origin clients reach (scheme+host,
			// no trailing slash). yauth builds token_endpoint / the metadata
			// `issuer` from it; if it disagrees with the host the client used,
			// strict OAuth clients reject the metadata. See the gotcha below.
			Issuer:                       "https://mcp.example.com",
			BasePath:                     "/api/auth", // MUST match the StripPrefix mount below
			DCREnabled:                   true,        // footgun #7: MCP clients self-register (RFC 7591)
			DCRRequireInitialAccessToken: &openDCR,    // footgun #7: allow anonymous registration
		})).
		Build()
}

func router(ya *yauth.YAuth, mcpHandler http.Handler, spa http.Handler) http.Handler {
	mux := http.NewServeMux()

	// 1. yauth itself, mounted under /api/auth.
	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))

	// 2. Root OAuth discovery so MCP clients can find the AS (footguns #1–#3).
	cfg := mcpauth.Config{
		AuthBasePath: "/api/auth",
		PublicURL:    "https://mcp.example.com", // pin discovery URLs (anti-spoof; matches Issuer)
		ConsentPath:  "/authorize",              // the SPA route that renders the consent UI
		ResourceName: "Example MCP",
		Scopes: []mcpauth.Scope{
			{Name: "mcp:read", Description: "Read your data through MCP tools"},
			{Name: "mcp:write", Description: "Make changes through MCP tools"},
		},
	}
	mcpauth.Mount(mux, ya, cfg)

	// 3. The MCP endpoint, guarded (footguns #4 + #6). Register both forms.
	guarded := mcpauth.Guard(ya, mcpHandler)
	mux.Handle("/mcp", guarded)
	mux.Handle("/mcp/", guarded)

	// 4. SPA catch-all LAST so it never shadows the routes above.
	mux.Handle("/", spa)
	return mux
}
```

That's the whole server side. `mcpauth.Mount` registers:

```
GET /.well-known/oauth-protected-resource           RFC 9728 (new)
GET /.well-known/oauth-authorization-server          RFC 8414, proxied + patched
GET /.well-known/oauth-authorization-server/{suffix} RFC 8414 §3.1 path form
GET /.well-known/openid-configuration[/{suffix}]     OIDC discovery, proxied
```

### What `Guard` does

`mcpauth.Guard` authenticates via yauth's full resolver chain (session cookie →
bearer → API key) and injects the resolved user so your MCP handler recovers it
with `middleware.AuthUserFromContext`. On failure it does the two things
yauth's `RequireAuth` does not:

- sets `WWW-Authenticate: Bearer resource_metadata="<origin>/.well-known/oauth-protected-resource"`
  so the client auto-discovers the AS, and
- answers `application/json` so MCP clients can parse the error.

`Guard` deliberately imposes **no** tenant/org policy — layer that in your own
handler from the injected `AuthUser`. If you do need tenant scoping (the
spacewombat pattern), wrap your handler in your own middleware *inside* `Guard`.

## Scopes per app

`mcpauth.Config.Scopes` is the single source of truth for which scopes your
resource understands and what each means. `Mount` advertises the names in both
the protected-resource metadata (`scopes_supported`) and the proxied
authorization-server metadata (overriding yauth's generic
`openid/email/profile`). The descriptions feed the consent UI. A different app
just passes a different catalog:

```go
// spacewombat
Scopes: []mcpauth.Scope{
	{Name: "query:read",   Description: "Run read-only queries against your telemetry"},
	{Name: "alerts:write", Description: "Create and manage alerts"},
}
```

Mirror the same catalog in the frontend so the consent screen shows plain
language (see below).

## Consent UI

yauth's `GET /oauth/authorize` returns a JSON **consent payload**
(`{ client, scopes, request_id, csrf_token }`), not a page. Something has to
render it and POST the decision to `/oauth2/consent`. The flow is two steps:

```
GET  /api/auth/oauth/authorize?<oauth params>   (session cookie) -> consent payload
POST /api/auth/oauth2/consent {request_id, csrf_token, approved} -> { redirect_url }
```

### SPA (SolidJS / Vue) — the default

Mount `OAuthConsentPage` at the same path you set as `ConsentPath` (`/authorize`).
It does the GET, redirects to login on 401, follows `redirect_url` when consent
already exists, and otherwise renders `ConsentScreen`.

```tsx
// SolidJS (@solidjs/router)
import { OAuthConsentPage } from "@yackey-labs/yauth-ui-solidjs";

const SCOPES = {
	"mcp:read": "Read your data through MCP tools",
	"mcp:write": "Make changes through MCP tools",
};

<Route path="/authorize" component={() => <OAuthConsentPage scopeDescriptions={SCOPES} />} />
```

```ts
// Vue (vue-router)
import { OAuthConsentPage } from "@yackey-labs/yauth-ui-vue";

const routes = [
	{ path: "/authorize", component: OAuthConsentPage, props: { scopeDescriptions: SCOPES } },
];
```

`ConsentScreen` is the presentational half if you want to drive the GET
yourself — pass `requestId`, `csrfToken`, `scopes`, and `scopeDescriptions`.

> Keep `scopeDescriptions` in sync with the Go `mcpauth.Config.Scopes` catalog —
> same keys, same wording.

### Non-SPA Go server — HTML fallback

If the server has no SPA (a pure tool backend like spacewombat), use the
server-rendered fallback instead of the components. It implements the same
two-step flow and renders scope descriptions from your `Config.Scopes`:

```go
mux.Handle("GET /authorize", mcpauth.HTMLConsentHandler(ya, mcpauth.ConsentConfig{
	Config:  cfg,            // reuse the same Config (scopes, AuthBasePath, …)
	AppName: "Example MCP",
	// LoginPath defaults to "/login"
}))
```

## Routing checklist

The placement footguns (#6), in order of how often they bite:

1. **Everything app-facing under `/api`** except the three fixed surfaces:
   `/api/auth/*` (yauth), `/mcp` (the tool endpoint), and the root
   `/.well-known/*` discovery docs. This keeps SPA client routes (`/authorize`,
   `/dashboard`, …) from colliding with backend handlers on a hard refresh.
2. **Register `/mcp` *and* `/mcp/`.** MCP clients sometimes request the
   trailing-slash form; without the second route it falls through to the SPA
   catch-all and the client gets `text/html`.
3. **SPA catch-all (`mux.Handle("/", …)`) is registered LAST.** Go's `ServeMux`
   resolves by specificity, but registering it last keeps intent obvious and
   avoids surprises with older muxes.
4. **The metadata URLs must resolve to where yauth is mounted.** Two knobs feed
   this:
   - `mcpauth.AuthBasePath` **must equal the `StripPrefix` mount** (`/api/auth`).
     `mcpauth` proxies yauth's internal paths and builds
     `authorization_servers` as `origin + AuthBasePath`, so a mismatch breaks
     discovery. This one is a hard requirement.
   - oauth2server's `Issuer + BasePath` must **sum** to that same mount. Either
     `Issuer="https://host"` + `BasePath="/api/auth"` (used here) or
     `Issuer="https://host/api/auth"` + `BasePath=""` (spacewombat's choice)
     works — both make `token_endpoint` etc. land on real routes. Pick one
     spelling and stay consistent.

### Issuer must match the public origin

`mcpauth` derives the URLs it emits (PRM `resource`, `authorization_servers`,
the patched `authorization_endpoint`) from the **request** — `Host` +
`X-Forwarded-Proto` — so they're automatically correct behind a proxy. But the
URLs yauth emits inside its own metadata (`token_endpoint`,
`registration_endpoint`, and the `issuer` field itself) come from the static
oauth2server `Issuer`. If those two disagree, you get a document whose `issuer`
is `https://a` but whose `authorization_endpoint` is `https://b`, and strict
OAuth clients reject it.

So: **set `Issuer` to the exact public origin clients reach** — `https://mcp.example.com`,
scheme included, no trailing slash, no path (unless you're using the
`Issuer=host/api/auth` + `BasePath=""` spelling). Behind Traefik/Cloudflare,
make sure `X-Forwarded-Proto` reaches the app so `mcpauth`'s side agrees. The
symptom in local testing: hitting `127.0.0.1` while `Issuer` says `localhost`
makes `token_endpoint` (localhost) and `authorization_endpoint` (127.0.0.1)
disagree — use one hostname consistently.

> OIDC is optional. `mcpauth.Mount` aliases `/.well-known/openid-configuration`
> to root, but it only returns a document if you also load the `oidc` plugin;
> without it the alias passes through yauth's 404. Pure OAuth 2.1 MCP clients use
> `oauth-authorization-server`, not `openid-configuration`, so this is fine.

## Verify it

```bash
# 1. PRM exists at root and points at the AS.
curl -s https://mcp.example.com/.well-known/oauth-protected-resource | jq
# { "resource": "https://mcp.example.com",
#   "authorization_servers": ["https://mcp.example.com/api/auth"], ... }

# 2. AS metadata at root; authorization_endpoint is your SPA route, not /oauth/authorize.
curl -s https://mcp.example.com/.well-known/oauth-authorization-server | jq .authorization_endpoint
# "https://mcp.example.com/authorize"

# 3. Unauthenticated /mcp returns a discoverable 401.
curl -i https://mcp.example.com/mcp
# HTTP/1.1 401 Unauthorized
# WWW-Authenticate: Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource"
# Content-Type: application/json

# 4. Add it to Claude Code — discovery + DCR + browser consent happen automatically.
claude mcp add --transport http example https://mcp.example.com/mcp
```

## Before / after (spacewombat)

spacewombat hand-rolled all of this on its app mux: a root PRM handler, a
`patchedOAuthMetadata` proxy, a `wellKnownProxy` normalizer, a WWW-Authenticate
block in its auth middleware, and an `oauthConsentPage` HTML template. With this
package that collapses to:

```go
mcpauth.Mount(mux, ya, cfg)
mux.Handle("/mcp", mcpauth.Guard(ya, mcpHandler)) // + tenant middleware inside, if needed
mux.Handle("/mcp/", mcpauth.Guard(ya, mcpHandler))
// consent: SPA <OAuthConsentPage/>, or mcpauth.HTMLConsentHandler for the HTML fallback
```

## Security

See [SECURITY.md](SECURITY.md) for the OWASP review of this surface — the open-DCR
+ redirect-uri-scheme XSS chain (fixed), Host-header pinning, clickjacking
defense, and the "open but bounded" DCR best-practice config. Two things to do at
the app layer that the helper can't: set `PublicURL`, and rate-limit
`/oauth/register`.

## Reference

- [`mcpauth` package](../../mcpauth) — `Mount`, `Guard`, `HTMLConsentHandler`, `Config`, `Scope`
- [SECURITY.md](SECURITY.md) — OWASP review + DCR best practices
- [oauth2server plugin](../../plugins/oauth2server) — the authorization server (authorize / consent / token / DCR)
- [MCP authorization spec](https://modelcontextprotocol.io/specification/draft/basic/authorization)
- RFC 9728 (Protected Resource Metadata), RFC 8414 (AS Metadata), RFC 7591 (Dynamic Client Registration)
