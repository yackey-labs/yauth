// Package mcpauth wires the root-level OAuth 2.1 discovery surface an MCP
// server needs in front of a yauth-go authorization server.
//
// # Why this package exists
//
// yauth registers every plugin route at the root of its own mux with an empty
// prefix (yauth.New(...).Router() is meant to be mounted under a prefix via
// http.StripPrefix("/api/auth", ...)). The oauth2server plugin therefore serves
// its RFC 8414 metadata at "{mount}/.well-known/oauth-authorization-server" —
// i.e. "/api/auth/.well-known/...". But the MCP authorization spec (and the
// OAuth clients that implement it, including Claude Code) discover the
// authorization server from two documents that MUST live at the resource
// server's ROOT:
//
//	GET /.well-known/oauth-protected-resource     (RFC 9728)
//	GET /.well-known/oauth-authorization-server   (RFC 8414)
//
// yauth cannot register these from a plugin because a plugin only sees the
// mount prefix, not the root mux. Every server that has stood up an MCP
// endpoint on yauth has therefore hand-rolled the same four pieces of glue:
//
//  1. a root /.well-known/oauth-protected-resource handler (RFC 9728), which
//     yauth does not emit at all;
//  2. a root (and RFC 8414 §3.1 path-suffixed) /.well-known/oauth-authorization-server
//     alias that proxies into yauth and rewrites authorization_endpoint to a
//     browser-facing consent page instead of yauth's JSON authorize endpoint;
//  3. a 401 that carries WWW-Authenticate: Bearer resource_metadata="…" so the
//     client can auto-discover the metadata, and an application/json body so MCP
//     clients can parse it (yauth's RequireAuth answers text/plain);
//  4. an HTML consent page for browser callers, because yauth's GET
//     /oauth/authorize returns a JSON consent payload, not a page.
//
// mcpauth.Mount handles (1) and (2); mcpauth.Guard handles (3); and the SPA
// ConsentScreen components in @yackey-labs/yauth-ui-solidjs /
// @yackey-labs/yauth-ui-vue (or HTMLConsentHandler here) handle (4).
//
// # Usage
//
//	mux := http.NewServeMux()
//	// yauth itself, mounted under /api/auth.
//	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))
//	// Root discovery so MCP clients can find the AS.
//	mcpauth.Mount(mux, ya, mcpauth.Config{
//		AuthBasePath: "/api/auth",
//		ConsentPath:  "/authorize", // your SPA route that renders ConsentScreen
//	})
//	// Guard the MCP endpoint; 401s now carry RFC 9728 WWW-Authenticate.
//	mux.Handle("/mcp", mcpauth.Guard(ya, mcpHandler))
//	mux.Handle("/mcp/", mcpauth.Guard(ya, mcpHandler))
package mcpauth

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"

	yauth "github.com/yackey-labs/yauth"
	"github.com/yackey-labs/yauth/middleware"
)

// Config describes how the yauth authorization server is exposed so mcpauth can
// build correct absolute URLs and proxy into it.
type Config struct {
	// AuthBasePath is the path prefix the yauth router is mounted under on the
	// root mux, e.g. "/api/auth". It is advertised as the authorization server
	// in the protected-resource metadata, so it must match the StripPrefix
	// mount exactly. Required.
	AuthBasePath string

	// PublicURL is the canonical external origin of this resource server, e.g.
	// "https://mcp.example.com" (scheme + host, no trailing slash). When set,
	// the discovery documents are built from it instead of the request's Host
	// header. Set it in production: it makes the documents immune to Host-header
	// spoofing / response cache-poisoning, and it keeps the URLs mcpauth emits
	// (resource, authorization_endpoint) consistent with the oauth2server
	// Issuer-derived URLs (token_endpoint, the metadata issuer) — a mismatch
	// makes strict OAuth clients reject the metadata. When empty, mcpauth falls
	// back to the request Host (handy for local dev behind no proxy).
	PublicURL string

	// ConsentPath is the in-app route that renders the consent UI (the SPA
	// ConsentScreen component, or HTMLConsentHandler for a non-SPA server),
	// e.g. "/authorize". Mount rewrites authorization_endpoint in the proxied
	// RFC 8414 / OIDC metadata to this path so a browser lands on the consent
	// page instead of yauth's JSON authorize endpoint. If empty, the raw yauth
	// authorize endpoint is advertised unchanged.
	ConsentPath string

	// Scopes is the app's scope catalog: the single source of truth for which
	// scopes this resource understands and what each one means. When set,
	// Mount advertises the scope names in BOTH the protected-resource metadata
	// (scopes_supported) and the proxied authorization-server metadata
	// (scopes_supported is overridden, replacing yauth's generic
	// openid/email/profile default). HTMLConsentHandler renders each scope's
	// Description so the user sees plain language, not raw scope strings — and
	// the same catalog, mirrored in TS, feeds the SPA ConsentScreen's
	// scopeDescriptions. Different apps just pass a different catalog. Optional.
	Scopes []Scope

	// ResourceName, when set, is echoed in the protected-resource metadata's
	// resource_name (RFC 9728 §2). Optional but nice for client consent UIs.
	ResourceName string
}

// Scope is one OAuth scope the resource understands, paired with the
// human-readable description shown on the consent screen.
type Scope struct {
	Name        string
	Description string
}

// names returns just the scope identifiers, in catalog order.
func (c Config) scopeNames() []string {
	if len(c.Scopes) == 0 {
		return nil
	}
	out := make([]string, len(c.Scopes))
	for i, s := range c.Scopes {
		out[i] = s.Name
	}
	return out
}

// Mount registers the root-level discovery endpoints on root:
//
//	GET /.well-known/oauth-protected-resource            (RFC 9728)
//	GET /.well-known/oauth-authorization-server          (RFC 8414, patched)
//	GET /.well-known/oauth-authorization-server/{suffix}  (RFC 8414 §3.1)
//	GET /.well-known/openid-configuration                (OIDC Discovery)
//	GET /.well-known/openid-configuration/{suffix}
//
// The oauth-authorization-server and openid-configuration documents are proxied
// out of ya.Router() so they always reflect yauth's real capabilities; only
// authorization_endpoint is rewritten (to Config.ConsentPath) so browsers reach
// the consent UI. All endpoints are public — no credential required — which is
// what the discovery spec mandates.
func Mount(root *http.ServeMux, ya *yauth.YAuth, cfg Config) {
	yaRouter := ya.Router()

	root.HandleFunc("GET /.well-known/oauth-protected-resource", protectedResource(cfg))

	asMeta := authServerMetadata(yaRouter, cfg)
	root.Handle("GET /.well-known/oauth-authorization-server", asMeta)
	// RFC 8414 §3.1 inserts the well-known segment between host and the issuer
	// path (".../oauth-authorization-server/api/auth"); some MCP clients probe
	// that form. Serve the same patched document for any suffix.
	root.Handle("GET /.well-known/oauth-authorization-server/", asMeta)

	oidc := proxyTo(yaRouter, "/.well-known/openid-configuration")
	root.Handle("GET /.well-known/openid-configuration", oidc)
	root.Handle("GET /.well-known/openid-configuration/", oidc)
}

// protectedResource serves RFC 9728 OAuth 2.0 Protected Resource Metadata. It
// points MCP clients at the yauth authorization server (Config.AuthBasePath)
// without any static client configuration.
func protectedResource(cfg Config) http.HandlerFunc {
	base := strings.TrimRight(cfg.AuthBasePath, "/")
	return func(w http.ResponseWriter, r *http.Request) {
		origin := cfg.originFor(r)
		doc := map[string]any{
			"resource":                 origin,
			"authorization_servers":    []string{origin + base},
			"bearer_methods_supported": []string{"header"},
		}
		if names := cfg.scopeNames(); len(names) > 0 {
			doc["scopes_supported"] = names
		}
		if cfg.ResourceName != "" {
			doc["resource_name"] = cfg.ResourceName
		}
		writeJSON(w, http.StatusOK, doc)
	}
}

// authServerMetadata proxies yauth's RFC 8414 document and rewrites
// authorization_endpoint to the in-app consent route so browser-driven PKCE
// flows render the consent UI instead of receiving JSON.
func authServerMetadata(yaRouter http.Handler, cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		status, _, body := proxyFetch(yaRouter, r, "/.well-known/oauth-authorization-server")
		if status != http.StatusOK {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_, _ = w.Write(body)
			return
		}
		var doc map[string]json.RawMessage
		if json.Unmarshal(body, &doc) != nil {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(body)
			return
		}
		if cfg.ConsentPath != "" {
			authz := cfg.originFor(r) + "/" + strings.TrimLeft(cfg.ConsentPath, "/")
			doc["authorization_endpoint"], _ = json.Marshal(authz)
		}
		// Advertise the app's scope catalog in place of yauth's generic
		// openid/email/profile default so clients request the right scopes.
		if names := cfg.scopeNames(); len(names) > 0 {
			doc["scopes_supported"], _ = json.Marshal(names)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(doc)
	}
}

// proxyTo returns a handler that serves the yauth response for internalPath
// verbatim. Used for OIDC discovery, which needs no rewriting.
func proxyTo(yaRouter http.Handler, internalPath string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		status, header, body := proxyFetch(yaRouter, r, internalPath)
		for k, vs := range header {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}
}

// proxyFetch replays r against yaRouter with the path rewritten to
// internalPath (yauth registers its routes at mux root, so the AuthBasePath
// prefix must be stripped). It returns the recorded status, headers, and body.
func proxyFetch(yaRouter http.Handler, r *http.Request, internalPath string) (int, http.Header, []byte) {
	rec := httptest.NewRecorder()
	r2 := r.Clone(r.Context())
	r2.URL.Path = internalPath
	yaRouter.ServeHTTP(rec, r2)
	res := rec.Result()
	defer res.Body.Close() //nolint:errcheck
	body, _ := io.ReadAll(res.Body)
	return res.StatusCode, res.Header, body
}

// Guard authenticates a request via yauth's full resolver chain (session
// cookie, then bearer / API-key resolvers) and, on success, injects the
// resolved AuthUser so downstream handlers recover it with
// middleware.AuthUserFromContext — exactly as RequireAuth would.
//
// On failure it does what an MCP client needs and RequireAuth does not:
//
//   - sets WWW-Authenticate: Bearer resource_metadata="<origin>/.well-known/oauth-protected-resource"
//     so the client auto-discovers the authorization server (RFC 9728 §5.1), and
//   - answers application/json, so MCP/REST clients get a parseable body instead
//     of yauth's text/plain "Unauthorized".
//
// Guard intentionally does not impose tenant/org policy — layer that in your
// own handler using the injected AuthUser. It is the thin auth seam that makes
// the MCP endpoint discoverable; everything domain-specific stays yours.
func Guard(ya *yauth.YAuth, next http.Handler) http.Handler {
	mw := ya.Middleware()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		au, err := mw.ResolveAuth(r)
		if err != nil || au == nil {
			rmURL := externalOrigin(r) + "/.well-known/oauth-protected-resource"
			w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+rmURL+`"`)
			writeJSON(w, http.StatusUnauthorized, map[string]string{
				"error":             "unauthorized",
				"error_description": "authentication required",
			})
			return
		}
		next.ServeHTTP(w, r.WithContext(middleware.WithAuthUser(r.Context(), au)))
	})
}

// originFor returns the canonical origin for the discovery documents: the
// configured PublicURL when set (spoofing-immune), otherwise the request Host.
func (c Config) originFor(r *http.Request) string {
	if c.PublicURL != "" {
		return strings.TrimRight(c.PublicURL, "/")
	}
	return externalOrigin(r)
}

// externalOrigin reconstructs the scheme://host the client actually reached,
// honoring X-Forwarded-Proto so the URLs are correct behind a TLS-terminating
// proxy (Traefik / Cloudflare), which is the common deployment.
func externalOrigin(r *http.Request) string {
	scheme := "https"
	if fwd := r.Header.Get("X-Forwarded-Proto"); fwd != "" {
		scheme = fwd
	} else if r.TLS == nil {
		scheme = "http"
	}
	return scheme + "://" + r.Host
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
