// Package emailpassword implements the email + password authentication
// plugin for yauth-go. It is the MVP plugin: every other authentication
// method (passkey, OAuth, MFA, magic link, bearer, api-key) is planned but
// not yet wired.
//
// Routes registered by Plugin.Routes (relative to the prefix passed in):
//
//	POST {prefix}/register         create account, set session cookie
//	POST {prefix}/login            verify password, set session cookie
//	POST {prefix}/logout           delete current session, clear cookie
//	GET  {prefix}/session          return current AuthUser  (RequireAuth)
//	POST {prefix}/change-password  rotate password           (RequireAuth)
package emailpassword

import (
	"net/http"

	"github.com/yackey-labs/yauth-go/plugin"
)

// Config tunes plugin behaviour. Zero value yields safe defaults.
type Config struct {
	// MinPasswordLength is the minimum password length accepted by
	// /register and /change-password. If zero, defaults to 12.
	MinPasswordLength int
	// RequireEmailVerification, when true, will reject /login for
	// unverified accounts. MVP leaves this off (false).
	RequireEmailVerification bool
}

// emailPasswordPlugin is an unexported implementation of plugin.Plugin.
type emailPasswordPlugin struct {
	cfg Config
}

// New constructs the email-password plugin.
func New(cfg Config) plugin.Plugin {
	if cfg.MinPasswordLength <= 0 {
		cfg.MinPasswordLength = 12
	}
	return &emailPasswordPlugin{cfg: cfg}
}

// Name implements plugin.Plugin.
func (p *emailPasswordPlugin) Name() string { return "email-password" }

// Routes implements plugin.Plugin.
func (p *emailPasswordPlugin) Routes(host plugin.PluginHost, mux *http.ServeMux, prefix string) {
	mw := host.Middleware()

	mux.Handle("POST "+prefix+"/register", http.HandlerFunc(p.handleRegister(host)))
	mux.Handle("POST "+prefix+"/login", http.HandlerFunc(p.handleLogin(host)))
	mux.Handle("POST "+prefix+"/logout", mw.RequireAuth(http.HandlerFunc(p.handleLogout(host))))
	mux.Handle("GET "+prefix+"/session", mw.RequireAuth(http.HandlerFunc(p.handleSession(host))))
	mux.Handle("POST "+prefix+"/change-password", mw.RequireAuth(http.HandlerFunc(p.handleChangePassword(host))))
}
