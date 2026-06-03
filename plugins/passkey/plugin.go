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

	"github.com/yackey-labs/yauth-go/middleware"
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

// Routes registers the passkey operations as huma-native typed handlers on the
// shared huma.API. The mux is retained in the signature for parity with the
// plugin interface but is no longer used directly.
//
// Middleware wiring is per-route, following the rule "StashHTTPHuma whenever a
// route consumes a JSON body, sets a cookie, or does custom query parsing —
// otherwise pure typed huma I/O":
//
//   - register/begin — RequireAuthHuma + StashHTTPHuma: no body to decode, but
//     its success body carries a *protocol.CredentialCreation (WebAuthn options)
//     emitted through the legacy default-escaping json.Encoder with a
//     "charset=utf-8" content type. Writing it onto the stashed writer keeps the
//     bytes (and header) byte-identical to the legacy handler.
//   - register/finish — RequireAuthHuma + StashHTTPHuma: needs the raw request
//     for the strict decodeJSON (DisallowUnknownFields) that keeps a malformed
//     body a 400 (a huma Body input would yield 422), and writes its 201 body
//     itself for byte-identity.
//   - login/begin — StashHTTPHuma (public): optional body decode + charset-exact
//     options response.
//   - login/finish — StashHTTPHuma (public): body decode (400 on malformed),
//     Set-Cookie on success, and a user body that may contain HTML-escapable
//     characters.
//   - list — RequireAuthHuma + StashHTTPHuma: custom paginationFromQuery tolerates
//     garbage query values (defaults) where huma query ints would 422.
//   - delete {id} — RequireAuthHuma only: path param + 204, no body/cookie. Pure
//     typed huma I/O.
func (p *passkeyPlugin) Routes(host plugin.PluginHost, mux plugin.Router, api huma.API, prefix string) {
	mw := host.Middleware()

	authStashMw := huma.Middlewares{
		middleware.StashHTTPHuma(api),
		middleware.RequireAuthHuma(api, mw),
	}
	authMw := huma.Middlewares{
		middleware.RequireAuthHuma(api, mw),
	}
	publicStashMw := huma.Middlewares{
		middleware.StashHTTPHuma(api),
	}
	sec := []map[string][]string{
		{"sessionCookie": {}},
		{"bearer": {}},
		{"apiKey": {}},
	}

	huma.Register(api, huma.Operation{
		OperationID: "passkey-register-begin",
		Method:      http.MethodPost,
		Path:        prefix + "/passkeys/register/begin",
		Summary:     "Start passkey registration; return CredentialCreation options",
		Tags:        []string{"passkey"},
		Security:    sec,
		Middlewares: authStashMw,
	}, p.handleRegisterBegin(host))

	huma.Register(api, huma.Operation{
		OperationID: "passkey-register-finish",
		Method:      http.MethodPost,
		Path:        prefix + "/passkeys/register/finish",
		Summary:     "Finalize attestation and store the credential",
		Tags:        []string{"passkey"},
		Security:    sec,
		Middlewares: authStashMw,
	}, p.handleRegisterFinish(host))

	huma.Register(api, huma.Operation{
		OperationID: "passkey-login-begin",
		Method:      http.MethodPost,
		Path:        prefix + "/passkey/login/begin",
		Summary:     "Start a passkey assertion; supports discoverable flow",
		Tags:        []string{"passkey"},
		Security:    []map[string][]string{},
		Middlewares: publicStashMw,
	}, p.handleLoginBegin(host))

	huma.Register(api, huma.Operation{
		OperationID: "passkey-login-finish",
		Method:      http.MethodPost,
		Path:        prefix + "/passkey/login/finish",
		Summary:     "Verify assertion and issue a session",
		Tags:        []string{"passkey"},
		Security:    []map[string][]string{},
		Middlewares: publicStashMw,
	}, p.handleLoginFinish(host))

	huma.Register(api, huma.Operation{
		OperationID: "passkey-list",
		Method:      http.MethodGet,
		Path:        prefix + "/passkeys",
		Summary:     "List the caller's passkeys",
		Tags:        []string{"passkey"},
		Security:    sec,
		Middlewares: authStashMw,
	}, p.handleList(host))

	huma.Register(api, huma.Operation{
		OperationID:   "passkey-delete",
		Method:        http.MethodDelete,
		Path:          prefix + "/passkeys/{id}",
		Summary:       "Delete one of the caller's passkeys",
		Tags:          []string{"passkey"},
		Security:      sec,
		DefaultStatus: http.StatusNoContent,
		Middlewares:   authMw,
	}, p.handleDelete(host))
}
