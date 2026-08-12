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
// triggering plugin (email-password, bearer) returns
// {require_mfa, pending_session_id} instead of issuing a real session.
//
// Finally it publishes a plugin.MFAVerifier on the host. /mfa/verify ends
// in a cookie session, which a native client cannot carry, so the bearer
// plugin completes the challenge through that verifier at
// POST {prefix}/token/mfa and answers with a token pair instead.
package mfa

import (
	"errors"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/yackey-labs/yauth/middleware"
	"github.com/yackey-labs/yauth/plugin"
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
// Every write-op uses a native huma typed Body (request schemas auto-derive;
// unknown fields → 422) and a typed Body output (huma marshals the response).
// Middleware is per-route, following the rule "StashHTTPHuma only when a route
// needs raw *http.Request / http.ResponseWriter access":
//
//   - setup / confirm / delete / backup-codes count / regenerate —
//     RequireAuthHuma only: no cookie to write and no need for the raw request,
//     so they are fully huma-native (typed Body in, typed Body out). The user is
//     recovered via AuthUserFromContext.
//   - verify — RequireAuthHuma is NOT applied (public: gated by the
//     pending-session id) but StashHTTPHuma IS: it needs the raw request to read
//     RequestIP / User-Agent and the writer to set the session cookie. The
//     request body and response are still native huma typed Body.
func (p *mfaPlugin) Routes(host plugin.PluginHost, mux plugin.Router, api huma.API, prefix string) {
	mw := host.Middleware()

	// A GATE, not a plain handler: the step-up decision must land before
	// observers act on the event (see PluginHost.RegisterEventGate), so
	// lockout does not clear its failure counter for a login that is still
	// waiting on a second factor — whatever order the plugins were
	// registered in.
	host.RegisterEventGate(&loginEventHandler{
		repo:              host.Repo(),
		encryptionKey:     p.cfg.EncryptionKey,
		pendingSessionTTL: pendingSessionTTL,
	})

	// Publish the challenge verifier so token-issuing plugins (bearer)
	// can complete the same challenge for a client that has no cookie.
	host.RegisterMFAVerifier(&challengeVerifier{p: p, host: host, repo: host.Repo()})

	authMw := huma.Middlewares{
		middleware.RequireAuthHuma(api, mw),
		// MFA enrolment/reset acts on the caller's own account. A service
		// account resolves to the human who minted its key, so it must not
		// reach these routes — it could otherwise strip that person's TOTP
		// and burn their backup codes.
		middleware.RequireUserPrincipalHuma(api),
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
		Middlewares: authMw,
	}, p.handleSetup(host))

	huma.Register(api, huma.Operation{
		OperationID: "mfa-totp-confirm",
		Method:      http.MethodPost,
		Path:        prefix + "/mfa/totp/confirm",
		Summary:     "Confirm + activate TOTP",
		Description: "Validate a TOTP code against the pending secret and mark it verified.",
		Tags:        []string{"mfa"},
		Security:    sec,
		Middlewares: authMw,
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
