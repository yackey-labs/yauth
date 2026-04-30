// Package mfa implements TOTP-based multi-factor authentication for
// yauth-go. It exposes setup / confirm / delete routes for managing a
// user's TOTP secret, a backup-code lifecycle, and a /verify endpoint
// that consumes a pending-session created by the email-password login
// flow when MFA is enabled.
//
// Routes registered by Plugin.Routes (relative to the prefix passed in):
//
//	POST   {prefix}/totp/setup              create unverified secret  (RequireAuth)
//	POST   {prefix}/totp/confirm            verify + activate secret  (RequireAuth)
//	DELETE {prefix}/totp                    remove secret + codes     (RequireAuth)
//	GET    {prefix}/backup-codes            unused-count              (RequireAuth)
//	POST   {prefix}/backup-codes/regenerate replace codes             (RequireAuth)
//	POST   {prefix}/verify                  consume pending session
//
// The plugin also registers an events.Handler that intercepts
// login.succeeded events: when the authenticating user has a verified
// TOTP secret, the handler creates a pending-session record in the
// challenge repository and returns a RequireMfa decision so the
// triggering plugin (email-password) returns {require_mfa, pending_session_id}
// instead of issuing a real session.
package mfa

import (
	"errors"
	"net/http"

	"github.com/yackey-labs/yauth-go/plugin"
)

// Config tunes plugin behaviour.
type Config struct {
	// EncryptionKey is a 32-byte AES-256 key used to encrypt TOTP
	// secrets at rest. REQUIRED — Build returns an error if the key
	// is the zero value.
	EncryptionKey [32]byte
	// Issuer is the otpauth:// issuer label rendered in authenticator
	// apps. Defaults to "yauth" when empty.
	Issuer string
}

// New constructs the MFA plugin. Returns an error if EncryptionKey is
// the zero value.
func New(cfg Config) (plugin.Plugin, error) {
	var zero [32]byte
	if cfg.EncryptionKey == zero {
		return nil, errors.New("mfa: EncryptionKey is required (32 random bytes)")
	}
	if cfg.Issuer == "" {
		cfg.Issuer = "yauth"
	}
	return &mfaPlugin{cfg: cfg}, nil
}

type mfaPlugin struct {
	cfg Config
}

func (p *mfaPlugin) Name() string { return "mfa" }

func (p *mfaPlugin) Routes(host plugin.PluginHost, mux *http.ServeMux, prefix string) {
	mw := host.Middleware()

	host.RegisterEventHandler(&loginEventHandler{
		repo:              host.Repo(),
		encryptionKey:     p.cfg.EncryptionKey,
		pendingSessionTTL: pendingSessionTTL,
	})

	mux.Handle("POST "+prefix+"/totp/setup", mw.RequireAuth(http.HandlerFunc(p.handleSetup(host))))
	mux.Handle("POST "+prefix+"/totp/confirm", mw.RequireAuth(http.HandlerFunc(p.handleConfirm(host))))
	mux.Handle("DELETE "+prefix+"/totp", mw.RequireAuth(http.HandlerFunc(p.handleDelete(host))))
	mux.Handle("GET "+prefix+"/backup-codes", mw.RequireAuth(http.HandlerFunc(p.handleBackupCodesCount(host))))
	mux.Handle("POST "+prefix+"/backup-codes/regenerate", mw.RequireAuth(http.HandlerFunc(p.handleRegenerateBackupCodes(host))))
	mux.Handle("POST "+prefix+"/verify", http.HandlerFunc(p.handleVerify(host)))
}
