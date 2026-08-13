// Package mfa implements TOTP-based multi-factor authentication for
// yauth-go. It exposes setup / confirm / delete routes for managing a
// user's TOTP secret, a backup-code lifecycle, and a /verify endpoint
// that consumes a pending-session created by the email-password login
// flow when MFA is enabled.
//
// Routes registered by Plugin.Routes (relative to the prefix passed in):
//
//	POST   {prefix}/mfa/totp/setup              issue candidate secret    (RequireAuth + step-up, rate-limited)
//	POST   {prefix}/mfa/totp/confirm            promote candidate secret  (RequireAuth)
//	DELETE {prefix}/mfa/totp                    remove secret + codes     (RequireAuth + step-up, rate-limited)
//	GET    {prefix}/mfa/backup-codes            unused-count              (RequireAuth)
//	POST   {prefix}/mfa/backup-codes/regenerate replace codes             (RequireAuth + step-up, rate-limited)
//	POST   {prefix}/mfa/verify                  consume pending session   (rate-limited)
//
// The three routes marked "step-up" change HOW THE ACCOUNT AUTHENTICATES, so
// authentication alone does not open them: a user who already has a verified
// factor must present a current TOTP or backup code in the X-MFA-Code header.
// Without that, a stolen session could disable the control that exists to
// survive a stolen session. Setup is also non-destructive — the candidate
// secret and codes live in a pending enrolment until /mfa/totp/confirm
// promotes them, so an abandoned setup no longer drops the account out of MFA.
//
// Those same three routes share the rate_limit.mfa_verify bucket with
// /mfa/verify and bearer's /token/mfa (one per-IP budget across all of them),
// and they honour an account lock on the failure path: a wrong X-MFA-Code is
// still the ordinary 403, but once the failures have locked the account the
// next one is answered with lockout's 429. Before that, holding a session was
// enough to guess a six-digit secret without limit and without ever tripping
// the lock the guessing itself had caused.
//
// TOTP codes are single-use (RFC 6238 §5.2): the time step of an accepted code
// is recorded, and that step and every earlier one are refused thereafter.
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
	"time"

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

	// POST /mfa/verify had no limiter, despite rate_limit.mfa_verify
	// being advertised in the schema and its defaults. Shared bucket with
	// the bearer /token/mfa route, which completes the same challenge —
	// and, since the step-up routes below check the same six-digit secret,
	// with those too. middleware.RateLimit keys its bucket on the op NAME
	// plus the client IP, so one value used on several routes (or several
	// values built from the same op) is one budget per IP: alternating
	// between routes cannot double an attacker's guesses.
	verifyRL := plugin.RateLimitFor(host, plugin.RateLimitMFAVerify, 10, 60*time.Second)

	authMw := huma.Middlewares{
		middleware.RequireAuthHuma(api, mw),
		// MFA enrolment/reset acts on the caller's own account, so only the
		// account owner acting in their own right may reach these routes. A
		// service account resolves to the human who minted its key, and a
		// delegated OAuth access token resolves to the user who consented to
		// a scope — neither of them is that person, and either could
		// otherwise strip their TOTP and burn their backup codes.
		//
		// This is authorization, not step-up: it decides WHO may ask. The
		// handlers additionally require the current factor to be presented
		// (see mfaPlugin.requireStepUp), which decides whether the asker can
		// prove they still hold the credential they are changing.
		middleware.RequireUserPrincipalHuma(api),
	}

	// The three routes that DEMAND a current second factor (setup, delete,
	// backup-code regenerate) were an unmetered oracle: requireStepUp
	// answers a wrong X-MFA-Code with a flat 403 and nothing in the stack
	// meters an authenticated route, so anyone riding a session — a stolen
	// cookie, an XSS payload — could walk 000000..999999 against a
	// six-digit secret at full speed, and validateTOTPStep accepts three of
	// those million per window. They share the mfa_verify bucket because
	// they are guessing the same secret /mfa/verify guesses.
	//
	// Deliberately NOT applied to mfa-backup-codes-count (a read a settings
	// page performs, with nothing to guess) or mfa-totp-confirm (it
	// validates a code against a CANDIDATE secret the caller was just shown
	// in full). Metering those would spend the same per-IP budget that MFA
	// LOGIN needs, which behind a NAT is one office sharing 10/min.
	stepUpMw := append(huma.Middlewares{middleware.RateLimitHuma(verifyRL)}, authMw...)

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
		Description: "Issue a candidate TOTP secret and a fresh set of backup codes. Neither replaces " +
			"the account's current second factor until POST /mfa/totp/confirm accepts a code for the " +
			"new secret, so an abandoned enrollment leaves existing MFA intact. When the account " +
			"already has a verified factor, a current code must be supplied in the " + StepUpHeader + " header.",
		Tags:        []string{"mfa"},
		Security:    sec,
		Middlewares: stepUpMw,
	}, p.handleSetup(host))

	huma.Register(api, huma.Operation{
		OperationID: "mfa-totp-confirm",
		Method:      http.MethodPost,
		Path:        prefix + "/mfa/totp/confirm",
		Summary:     "Confirm + activate TOTP",
		Description: "Validate a code against the pending secret and promote it to the account's second " +
			"factor, replacing any previous secret and backup codes. The confirming code is recorded as " +
			"spent and cannot be reused to sign in.",
		Tags:        []string{"mfa"},
		Security:    sec,
		Middlewares: authMw,
	}, p.handleConfirm(host))

	huma.Register(api, huma.Operation{
		OperationID: "mfa-totp-delete",
		Method:      http.MethodDelete,
		Path:        prefix + "/mfa/totp",
		Summary:     "Disable TOTP",
		Description: "Remove the user's TOTP secret and all backup codes. Requires the current code in " +
			"the " + StepUpHeader + " header — the factor being removed must be presented to remove it.",
		Tags:        []string{"mfa"},
		Security:    sec,
		Middlewares: stepUpMw,
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
		Description: "Replace all backup codes with a fresh set, invalidating the ones already issued. " +
			"When the account has a verified factor, a current code must be supplied in the " +
			StepUpHeader + " header.",
		Tags:        []string{"mfa"},
		Security:    sec,
		Middlewares: stepUpMw,
	}, p.handleRegenerateBackupCodes(host))

	huma.Register(api, huma.Operation{
		OperationID: "mfa-verify",
		Method:      http.MethodPost,
		Path:        prefix + "/mfa/verify",
		Summary:     "Verify an MFA challenge",
		Description: "Consume a pending-session created by the login flow and issue a real session.",
		Tags:        []string{"mfa"},
		Security:    []map[string][]string{}, // public: gated by the pending-session id
		// Rate-limited on rate_limit.mfa_verify. The pending session is
		// single-use, so one challenge cannot be brute-forced — but
		// nothing stopped an attacker holding a valid password from
		// opening challenge after challenge and guessing a fresh
		// six-digit code at each one.
		Middlewares: huma.Middlewares{middleware.RateLimitHuma(verifyRL), middleware.StashHTTPHuma(api)},
	}, p.handleVerify(host))
}
