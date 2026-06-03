// Package oauth implements the multi-provider OAuth/OIDC client plugin
// for yauth-go. It supports Google, GitHub, and any generic OpenID Connect
// provider out of the box, plus arbitrary custom providers that implement
// the Provider interface.
//
// Routes registered (relative to the prefix passed in):
//
//	GET  {prefix}/oauth/{provider}/authorize  begin auth-code flow, set
//	                                          state cookie, redirect
//	GET  {prefix}/oauth/{provider}/callback   exchange code, link/create
//	                                          user, issue session
//	POST {prefix}/oauth/{provider}/callback   form-post variant of GET callback
//	GET  {prefix}/oauth/accounts              list current user's links
//	                                          (RequireAuth)
//	DELETE {prefix}/oauth/{provider}          unlink (RequireAuth);
//	                                          refuses if it would lock
//	                                          the user out (no password
//	                                          and no other links)
//	POST {prefix}/oauth/{provider}/link       start linking flow for
//	                                          already-authed user
//	                                          (RequireAuth)
//
// At-rest token storage is AES-256-GCM via crypto.go. The 32-byte key is
// supplied via Config.EncryptionKey.
package oauth

import (
	"github.com/danielgtaylor/huma/v2"

	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/yackey-labs/yauth-go/plugin"
)

// Config tunes the oauth plugin.
type Config struct {
	// EncryptionKey is the 32-byte AES-256-GCM key used to encrypt
	// access/refresh tokens at rest. The zero value is rejected by Build
	// — callers MUST supply a real key.
	EncryptionKey [32]byte

	// Providers is the list of registered OAuth providers. The plugin
	// indexes them by Name(); duplicate names are rejected by Build.
	// Empty slices are rejected by Build.
	Providers []Provider

	// StateTTL bounds how long an authorization-code flow may take from
	// /authorize to /callback. Defaults to 10 minutes if zero.
	StateTTL time.Duration

	// AllowedRedirectURLs is the allow-list of post-login redirect targets
	// the plugin will honor on the redirect_url query parameter of
	// /authorize and /link. Each entry is matched as an exact-prefix on
	// the incoming URL after trimming whitespace; relative paths (starting
	// with "/") are always accepted.
	//
	// Empty / nil slice means "redirect_url is ignored entirely" — the
	// callback always lands at the host's BaseURL. This is the safest
	// default and matches the open-redirect mitigation surfaced by the
	// pentest suite (TestPentest_OAuthOpenRedirect_NotEnforced).
	//
	// Operators who want flexible post-login redirects MUST supply this
	// list explicitly: e.g. AllowedRedirectURLs: []string{"https://app.example.com"}.
	AllowedRedirectURLs []string
}

// oauthPlugin implements plugin.Plugin.
type oauthPlugin struct {
	cfg       Config
	providers map[string]Provider
}

// New constructs the oauth plugin. Returns a non-nil error when the config
// is invalid (zero key, no providers, duplicate provider names).
func New(cfg Config) (plugin.Plugin, error) {
	if cfg.EncryptionKey == ([32]byte{}) {
		return nil, errors.New("oauth: Config.EncryptionKey is required (zero value rejected)")
	}
	if len(cfg.Providers) == 0 {
		return nil, errors.New("oauth: Config.Providers must contain at least one provider")
	}
	if cfg.StateTTL <= 0 {
		cfg.StateTTL = 10 * time.Minute
	}
	idx := make(map[string]Provider, len(cfg.Providers))
	for _, p := range cfg.Providers {
		if p == nil {
			return nil, errors.New("oauth: nil provider in Config.Providers")
		}
		name := p.Name()
		if name == "" {
			return nil, errors.New("oauth: provider with empty Name()")
		}
		if _, exists := idx[name]; exists {
			return nil, fmt.Errorf("oauth: duplicate provider name %q", name)
		}
		idx[name] = p
	}
	return &oauthPlugin{cfg: cfg, providers: idx}, nil
}

// MustNew is the panic-on-error variant of New, suited to the builder
// chain where a misconfiguration is a programmer error rather than a
// runtime condition.
func MustNew(cfg Config) plugin.Plugin {
	p, err := New(cfg)
	if err != nil {
		panic(err)
	}
	return p
}

// Name implements plugin.Plugin.
func (p *oauthPlugin) Name() string { return "oauth" }

// Routes implements plugin.Plugin.
func (p *oauthPlugin) Routes(host plugin.PluginHost, mux plugin.Router, api huma.API, prefix string) {
	mw := host.Middleware()

	mux.Handle("GET "+prefix+"/oauth/{provider}/authorize", http.HandlerFunc(p.handleAuthorize(host)))
	mux.Handle("GET "+prefix+"/oauth/{provider}/callback", http.HandlerFunc(p.handleCallback(host)))
	mux.Handle("POST "+prefix+"/oauth/{provider}/callback", http.HandlerFunc(p.handleCallback(host)))
	mux.Handle("GET "+prefix+"/oauth/accounts", mw.RequireAuth(http.HandlerFunc(p.handleListAccounts(host))))
	mux.Handle("DELETE "+prefix+"/oauth/{provider}", mw.RequireAuth(http.HandlerFunc(p.handleUnlink(host))))
	mux.Handle("POST "+prefix+"/oauth/{provider}/link", mw.RequireAuth(http.HandlerFunc(p.handleLink(host))))
}
