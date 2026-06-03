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
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/yackey-labs/yauth-go/plugin"
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
}

const defaultTokenTTL = 15 * time.Minute

type magicLinkPlugin struct {
	cfg Config
}

// New constructs the magic-link plugin.
func New(cfg Config) plugin.Plugin {
	if cfg.TokenTTL <= 0 {
		cfg.TokenTTL = defaultTokenTTL
	}
	if cfg.Mailer == nil {
		cfg.Mailer = LoggingMailer{}
	}
	return &magicLinkPlugin{cfg: cfg}
}

// Name implements plugin.Plugin.
func (p *magicLinkPlugin) Name() string { return "magic-link" }

// Routes implements plugin.Plugin. Both routes are huma-native, public
// (no auth gate, mirroring the passwordless flow), and use StashHTTPHuma to
// reach the underlying *http.Request / http.ResponseWriter so the migrated
// handlers keep byte-identical body parsing (strict decode, the
// enumeration-safe send semantics) and the verify route's Set-Cookie write.
// The input structs carry NO huma Body field, so huma leaves the request body
// intact for the plugin's own strict decoder. The mux is retained in the
// signature for plugins that still register raw net/http routes; magic-link no
// longer uses it.
func (p *magicLinkPlugin) Routes(host plugin.PluginHost, mux plugin.Router, api huma.API, prefix string) {
	p.registerSend(host, api, prefix)
	p.registerVerify(host, api, prefix)
}
