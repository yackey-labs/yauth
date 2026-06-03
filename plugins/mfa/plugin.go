// Package mfa implements TOTP-based multi-factor authentication for
// yauth-go. It exposes setup / confirm / delete routes for managing a
// user's TOTP secret, a backup-code lifecycle, and a /verify endpoint
// that consumes a pending-session created by the email-password login
// flow when MFA is enabled.
//
// Routes registered by Plugin.Routes (relative to the prefix passed in):
//
//	POST   {prefix}/mfa/totp/setup              create unverified secret  (RequireAuth)
//	POST   {prefix}/mfa/totp/confirm            verify + activate secret  (RequireAuth)
//	DELETE {prefix}/mfa/totp                    remove secret + codes     (RequireAuth)
//	GET    {prefix}/mfa/backup-codes            unused-count              (RequireAuth)
//	POST   {prefix}/mfa/backup-codes/regenerate replace codes             (RequireAuth)
//	POST   {prefix}/mfa/verify                  consume pending session
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

	"github.com/danielgtaylor/huma/v2"

	"github.com/yackey-labs/yauth-go/middleware"
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

// Routes registers the MFA operations as huma-native typed handlers on the
// shared huma.API. The mux is retained in the signature for parity with the
// plugin interface but is no longer used.
//
// Middleware wiring is per-route, following the rule "StashHTTPHuma only when a
// route needs raw *http.Request / http.ResponseWriter access":
//
//   - setup  — RequireAuthHuma + StashHTTPHuma: its response carries an
//     otpauth_url containing '&', which the legacy handler emits HTML-escaped
//     ('&'). huma's Body marshaler disables HTML escaping, so to stay
//     byte-identical the handler writes the body itself onto the stashed writer.
//   - confirm — RequireAuthHuma + StashHTTPHuma: needs the raw request for the
//     strict decodeJSON (DisallowUnknownFields) that keeps a malformed body a
//     400 (a huma Body input would yield 422). Its success body is a fixed
//     string with no special chars, returned via huma Body.
//   - delete / backup-codes count / regenerate — RequireAuthHuma only: no body
//     to decode, no cookie to write, and their responses contain no '&'/'<'/'>'
//     so huma's Body marshaler is byte-identical. They return typed Body outputs.
//   - verify — StashHTTPHuma only (unauthenticated; gated by the pending-session
//     id): needs the raw request to decode the body and read RequestIP/UA, the
//     writer to set the session cookie, and manual writeJSON because the user's
//     display_name/email may contain HTML-escapable characters.
func (p *mfaPlugin) Routes(host plugin.PluginHost, mux plugin.Router, api huma.API, prefix string) {
	mw := host.Middleware()

	host.RegisterEventHandler(&loginEventHandler{
		repo:              host.Repo(),
		encryptionKey:     p.cfg.EncryptionKey,
		pendingSessionTTL: pendingSessionTTL,
	})

	authStashMw := huma.Middlewares{
		middleware.StashHTTPHuma(api),
		middleware.RequireAuthHuma(api, mw),
	}
	authMw := huma.Middlewares{
		middleware.RequireAuthHuma(api, mw),
	}
	sec := []map[string][]string{
		{"sessionCookie": {}},
		{"bearer": {}},
		{"apiKey": {}},
	}

	huma.Register(api, huma.Operation{
		OperationID: "mfa-totp-setup",
		Method:      http.MethodPost,
		Path:        prefix + "/mfa/totp/setup",
		Summary:     "Begin TOTP enrollment",
		Description: "Create (or reset) an unverified TOTP secret and a fresh set of backup codes.",
		Tags:        []string{"mfa"},
		Security:    sec,
		Middlewares: authStashMw,
	}, p.handleSetup(host))

	huma.Register(api, huma.Operation{
		OperationID: "mfa-totp-confirm",
		Method:      http.MethodPost,
		Path:        prefix + "/mfa/totp/confirm",
		Summary:     "Confirm + activate TOTP",
		Description: "Validate a TOTP code against the pending secret and mark it verified.",
		Tags:        []string{"mfa"},
		Security:    sec,
		Middlewares: authStashMw,
	}, p.handleConfirm(host))

	huma.Register(api, huma.Operation{
		OperationID: "mfa-totp-delete",
		Method:      http.MethodDelete,
		Path:        prefix + "/mfa/totp",
		Summary:     "Disable TOTP",
		Description: "Remove the user's TOTP secret and all backup codes.",
		Tags:        []string{"mfa"},
		Security:    sec,
		Middlewares: authMw,
	}, p.handleDelete(host))

	huma.Register(api, huma.Operation{
		OperationID: "mfa-backup-codes-count",
		Method:      http.MethodGet,
		Path:        prefix + "/mfa/backup-codes",
		Summary:     "Count unused backup codes",
		Tags:        []string{"mfa"},
		Security:    sec,
		Middlewares: authMw,
	}, p.handleBackupCodesCount(host))

	huma.Register(api, huma.Operation{
		OperationID: "mfa-backup-codes-regenerate",
		Method:      http.MethodPost,
		Path:        prefix + "/mfa/backup-codes/regenerate",
		Summary:     "Regenerate backup codes",
		Description: "Replace all backup codes with a fresh set.",
		Tags:        []string{"mfa"},
		Security:    sec,
		Middlewares: authMw,
	}, p.handleRegenerateBackupCodes(host))

	huma.Register(api, huma.Operation{
		OperationID: "mfa-verify",
		Method:      http.MethodPost,
		Path:        prefix + "/mfa/verify",
		Summary:     "Verify an MFA challenge",
		Description: "Consume a pending-session created by the login flow and issue a real session.",
		Tags:        []string{"mfa"},
		Security:    []map[string][]string{}, // public: gated by the pending-session id
		Middlewares: huma.Middlewares{middleware.StashHTTPHuma(api)},
	}, p.handleVerify(host))
}
