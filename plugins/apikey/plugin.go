// Package apikey implements the X-Api-Key authentication plugin for
// yauth-go. It provides:
//
//   - A long-lived prefix+secret credential format ("yak_<prefix>_<secret>").
//   - An AuthResolver that reads the X-Api-Key header on every request
//     and authenticates the bearer.
//   - Authenticated handlers that let the holder list, create, and revoke
//     their own keys.
//
// Routes registered by Plugin.Routes (relative to the prefix passed in):
//
//	GET    {prefix}/api-keys         list current user's keys (RequireAuth)
//	POST   {prefix}/api-keys         create new key (RequireAuth)
//	DELETE {prefix}/api-keys/{id}    revoke key by id (RequireAuth)
//
// Storage:
//
//   - key_prefix is stored plain — used as the lookup index.
//   - key_hash is the SHA-256 hex digest of the secret, verified
//     constant-time on every request.
//   - The plaintext key is returned exactly once (POST response) and is
//     never recoverable thereafter.
package apikey

import (
	"github.com/danielgtaylor/huma/v2"

	"net/http"

	"github.com/yackey-labs/yauth-go/plugin"
)

// defaultPrefix is the prefix-tag used when Config.Prefix is unset.
const defaultPrefix = "yak"

// defaultMaxKeysPerUser caps how many active keys a single user can own.
const defaultMaxKeysPerUser = 25

// Config tunes plugin behaviour. Zero value yields safe defaults.
type Config struct {
	// Prefix is the leading identifier ("<prefix>_<8hex>_<32hex>") used to
	// recognise an API key in the X-Api-Key header. Defaults to "yak".
	Prefix string

	// MaxKeysPerUser caps the number of keys a single user may own. The
	// /api-keys POST handler rejects with 409 once this is reached.
	// Defaults to 25.
	MaxKeysPerUser int
}

// apiKeyPlugin is an unexported implementation of plugin.Plugin.
type apiKeyPlugin struct {
	cfg Config
}

// New constructs the api-key plugin.
func New(cfg Config) plugin.Plugin {
	if cfg.Prefix == "" {
		cfg.Prefix = defaultPrefix
	}
	if cfg.MaxKeysPerUser <= 0 {
		cfg.MaxKeysPerUser = defaultMaxKeysPerUser
	}
	return &apiKeyPlugin{cfg: cfg}
}

// Name implements plugin.Plugin.
func (p *apiKeyPlugin) Name() string { return "api-key" }

// Routes implements plugin.Plugin. It registers the X-Api-Key resolver on
// the host so subsequent middleware-wrapped routes (in this plugin and
// elsewhere) can authenticate via header, and mounts the management
// endpoints under prefix/api-keys.
func (p *apiKeyPlugin) Routes(host plugin.PluginHost, mux *http.ServeMux, api huma.API, prefix string) {
	mw := host.Middleware()

	host.RegisterAuthResolver(newResolver(host, p.cfg.Prefix))

	mux.Handle("GET "+prefix+"/api-keys", mw.RequireAuth(http.HandlerFunc(p.handleList(host))))
	mux.Handle("POST "+prefix+"/api-keys", mw.RequireAuth(http.HandlerFunc(p.handleCreate(host))))
	mux.Handle("DELETE "+prefix+"/api-keys/{id}", mw.RequireAuth(http.HandlerFunc(p.handleDelete(host))))
}
