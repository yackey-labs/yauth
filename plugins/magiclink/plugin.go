// Package magiclink implements a passwordless email-link sign-in plugin.
//
// Routes registered by Plugin.Routes (relative to the prefix passed in):
//
//	POST {prefix}/magic-link/send    — request a single-use login link
//	POST {prefix}/magic-link/verify  — exchange the token for a session
//
// /send always returns 200 {"sent": true} regardless of whether the email
// matches an existing user; this prevents user enumeration. The link is
// delivered via the configured Mailer; the default LoggingMailer prints
// to stderr so the workflow is usable in development without an SMTP
// dependency.
package magiclink

import (
	"log/slog"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/yackey-labs/yauth/plugin"
)

// Config tunes plugin behaviour. Zero value yields safe defaults.
type Config struct {
	// TokenTTL controls how long an issued magic-link token remains
	// usable. Defaults to 15 minutes when unset.
	TokenTTL time.Duration

	// SignupEnabled controls whether /verify will create a new account
	// for an email it has never seen before. When false (default), the
	// only way to authenticate via magic-link is for an existing user.
	SignupEnabled bool

	// Mailer delivers the generated link to the requester. When nil,
	// LoggingMailer is used (stderr-only) so dev setups need no SMTP.
	Mailer Mailer

	// LinkBaseURL is prepended to the raw token to form the link
	// embedded in the outgoing email. Example: "https://app.example.com
	// /magic". The plugin appends "?token=<raw>".
	LinkBaseURL string

	// SatisfiesMFA declares that presenting a valid magic link is itself
	// enough to count as the second factor, so a TOTP-enrolled user is NOT
	// stepped up after clicking the link.
	//
	// The default (false) steps up: a magic link proves control of an
	// inbox and nothing more, which is the same class of evidence as a
	// password — and usually the SAME channel the password reset uses, so
	// treating it as a second factor collapses both factors onto one
	// mailbox. /magic-link/verify therefore answers {require_mfa,
	// pending_session_id} and sets no cookie until POST /mfa/verify
	// completes the login, exactly as the cookie password login does.
	//
	// Set true only where the mail channel is itself strongly protected
	// and the operator has decided the link is a factor of its own.
	SatisfiesMFA bool
}

const defaultTokenTTL = 15 * time.Minute

type magicLinkPlugin struct {
	cfg    Config
	logger *slog.Logger
}

// New constructs the magic-link plugin.
func New(cfg Config) plugin.Plugin {
	if cfg.TokenTTL <= 0 {
		cfg.TokenTTL = defaultTokenTTL
	}
	if cfg.Mailer == nil {
		cfg.Mailer = &LoggingMailer{}
	}
	return &magicLinkPlugin{cfg: cfg}
}

// Name implements plugin.Plugin.
func (p *magicLinkPlugin) Name() string { return "magic-link" }

// Routes implements plugin.Plugin. Both routes are huma-native and public (no
// auth gate, mirroring the passwordless flow). The request bodies are native
// huma typed Body fields, so huma parses + validates them and the OpenAPI
// request schemas auto-derive. /verify additionally uses StashHTTPHuma to reach
// the underlying *http.Request (RequestIP / User-Agent) and http.ResponseWriter
// for its Set-Cookie write; /send needs neither and uses no bridge. The mux is
// retained in the signature for plugins that still register raw net/http routes;
// magic-link no longer uses it.
func (p *magicLinkPlugin) Routes(host plugin.PluginHost, mux plugin.Router, api huma.API, prefix string) {
	p.logger = host.Logger()
	if lm, ok := p.cfg.Mailer.(*LoggingMailer); ok {
		lm.logger = p.logger
		p.logger.Warn("magic-link: using the console LoggingMailer — login links (single-use tokens) are written to logs and NO email is sent; set Config.Mailer for production")
	}
	p.registerSend(host, api, prefix)
	p.registerVerify(host, api, prefix)
}
