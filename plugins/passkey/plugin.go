// Package passkey implements WebAuthn / passkey authentication for yauth-go.
//
// Routes registered by Plugin.Routes (relative to the prefix passed in):
//
//	POST {prefix}/passkeys/register/begin   (auth)  - obtain CredentialCreation options
//	POST {prefix}/passkeys/register/finish  (auth)  - finalize attestation, store credential
//	POST {prefix}/passkey/login/begin               - obtain CredentialAssertion options
//	POST {prefix}/passkey/login/finish              - verify assertion, issue session
//	GET  {prefix}/passkeys                  (auth)  - list caller's credentials
//	DELETE {prefix}/passkeys/{id}           (auth)  - delete one of caller's credentials
//
// End-to-end exercise of these routes requires a real authenticator (browser
// + platform/security key). The upstream go-webauthn library does not ship a
// virtual authenticator, so the test suite here covers only the bits that do
// not require one: the User adapter, JSON round-trips, and the shape of
// /begin responses.
package passkey

import (
	"github.com/danielgtaylor/huma/v2"

	"fmt"
	"net/http"

	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/yackey-labs/yauth-go/plugin"
)

// Config tunes passkey behaviour.
type Config struct {
	// RPID is the Relying Party identifier (effective domain), e.g. "localhost"
	// or "example.com". Required.
	RPID string
	// RPOrigins is the list of allowed origins (scheme://host[:port]) the
	// browser may present, e.g. ["http://localhost:3000"]. Required.
	RPOrigins []string
	// RPName is the human-readable display name shown in the platform UI.
	// Defaults to "yauth".
	RPName string
}

// passkeyPlugin is an unexported implementation of plugin.Plugin.
type passkeyPlugin struct {
	cfg Config
	wa  *webauthn.WebAuthn
}

// New constructs the passkey plugin. Returns an error if the configured
// RP identifier / origins are rejected by the underlying webauthn library.
func New(cfg Config) (plugin.Plugin, error) {
	if cfg.RPID == "" {
		return nil, fmt.Errorf("passkey: Config.RPID is required")
	}
	if len(cfg.RPOrigins) == 0 {
		return nil, fmt.Errorf("passkey: Config.RPOrigins must contain at least one origin")
	}
	if cfg.RPName == "" {
		cfg.RPName = "yauth"
	}

	wa, err := webauthn.New(&webauthn.Config{
		RPID:          cfg.RPID,
		RPDisplayName: cfg.RPName,
		RPOrigins:     cfg.RPOrigins,
	})
	if err != nil {
		return nil, fmt.Errorf("passkey: build webauthn: %w", err)
	}

	return &passkeyPlugin{cfg: cfg, wa: wa}, nil
}

// Name implements plugin.Plugin.
func (p *passkeyPlugin) Name() string { return "passkey" }

// Routes implements plugin.Plugin.
func (p *passkeyPlugin) Routes(host plugin.PluginHost, mux plugin.Router, api huma.API, prefix string) {
	mw := host.Middleware()

	mux.Handle("POST "+prefix+"/passkeys/register/begin", mw.RequireAuth(http.HandlerFunc(p.handleRegisterBegin(host))))
	mux.Handle("POST "+prefix+"/passkeys/register/finish", mw.RequireAuth(http.HandlerFunc(p.handleRegisterFinish(host))))

	mux.Handle("POST "+prefix+"/passkey/login/begin", http.HandlerFunc(p.handleLoginBegin(host)))
	mux.Handle("POST "+prefix+"/passkey/login/finish", http.HandlerFunc(p.handleLoginFinish(host)))

	mux.Handle("GET "+prefix+"/passkeys", mw.RequireAuth(http.HandlerFunc(p.handleList(host))))
	mux.Handle("DELETE "+prefix+"/passkeys/{id}", mw.RequireAuth(http.HandlerFunc(p.handleDelete(host))))
}
