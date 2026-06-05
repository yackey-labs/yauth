package yauth

import (
	"net/http"
	"strings"
)

// MountOptions controls how Mount attaches yauth onto a consumer's
// http.ServeMux. The zero value is the recommended default: the API under
// "/api/auth" and .well-known discovery aliased at the host root.
type MountOptions struct {
	// APIPrefix is the path the API router mounts under. Empty means the
	// ecosystem default "/api/auth" (the Vue/SolidJS components' baseUrl
	// defaults to the same path). A trailing slash is ignored. Setting it
	// explicitly to "/" mounts the router at the root with no StripPrefix
	// (and no separate root .well-known alias — the root already covers it).
	APIPrefix string

	// DiscoveryAtRoot controls whether the OIDC/OAuth discovery documents
	// and JWKS are ALSO served at the host root (/.well-known/...), in
	// addition to under APIPrefix. nil means true — root discovery is the
	// default because it matches the single-tenant IdP norm (issuer = bare
	// origin, discovery at the origin root: Okta org server, Google,
	// GitLab). Set it to an explicit false to keep discovery only under the
	// prefix.
	DiscoveryAtRoot *bool
}

// Mount attaches yauth to mux in the turnkey single-tenant-IdP layout: the
// API under a path prefix, with OIDC/OAuth discovery and JWKS aliased at the
// host root. It is additive ergonomics over the low-level Router(); advanced
// consumers who need custom routing can keep calling Router() directly.
//
// With the zero MountOptions it registers, on mux:
//
//	GET/POST /api/auth/...                 → StripPrefix("/api/auth", y.Router())
//	GET      /api/auth                     → 301 redirect to /api/auth/
//	GET      /.well-known/...              → y.Router() (NOT stripped)
//
// The root /.well-known/ mount is unstripped on purpose: y.Router() serves its
// discovery docs (/.well-known/openid-configuration,
// /.well-known/oauth-authorization-server, /.well-known/jwks.json) at its own
// root, so handing the root path straight through makes those reachable at the
// host root in addition to under the prefix. Both mount points return the SAME
// document because the discovery doc is built from the configured Issuer/
// BasePath, not from the request's path or Host.
//
// # Correctness: root discovery requires issuer = bare origin
//
// Serving discovery at the host root is only valid when the OIDC "issuer" is
// the bare origin, because an RP that fetches {issuer}/.well-known/... and finds
// a document whose "issuer" field differs will reject it. So configure the
// oidc/oauth2server plugins with:
//
//	Issuer:   "https://idp.example.com"   // the bare origin
//	BasePath: "/api/auth"                 // == APIPrefix
//
// The discovery doc then reports issuer = "https://idp.example.com" (matching
// https://idp.example.com/.well-known/... at the root) while
// authorization_endpoint / token_endpoint / jwks_uri point under
// https://idp.example.com/api/auth/... An issuer that differs from the endpoint
// base is valid OIDC — it is exactly what Okta's org server and Google do. Do
// NOT make the issuer your API mount path; path-carried issuers
// (e.g. /realms/{realm}) are a multi-tenant pattern, not this one.
func (y *YAuth) Mount(mux *http.ServeMux, opts MountOptions) {
	router := y.Router()

	// An unset APIPrefix means the ecosystem default. An explicit "/" (or
	// "//", etc.) means "mount at the root" — distinct from unset.
	prefix := opts.APIPrefix
	if prefix == "" {
		prefix = "/api/auth"
	}
	prefix = strings.TrimRight(prefix, "/")

	if prefix == "" {
		// Explicit root mount: the router owns the whole tree, including
		// /.well-known/, so there is nothing to strip, redirect, or alias.
		mux.Handle("/", router)
		return
	}

	mux.Handle(prefix+"/", http.StripPrefix(prefix, router))
	// Registering the exact path alongside the subtree suppresses the mux's
	// automatic redirect so this explicit, predictable one controls it.
	mux.Handle(prefix, http.RedirectHandler(prefix+"/", http.StatusMovedPermanently))

	discoveryAtRoot := opts.DiscoveryAtRoot == nil || *opts.DiscoveryAtRoot
	if discoveryAtRoot {
		// Unstripped: y.Router() serves the discovery docs at its own root.
		mux.Handle("/.well-known/", router)
	}
}
