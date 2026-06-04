// Package status implements a tiny diagnostic plugin that reports the
// names of every plugin currently registered on the host along with a
// version string.
//
// Routes registered by Plugin.Routes (relative to the prefix passed in):
//
//	GET {prefix}/status   admin-only — returns {plugins: [...names], version: "..."}
//	GET {prefix}/config   public     — returns subset of host config (yauth parity)
//
// `/config` is intentionally unauthenticated — SPAs call it at boot to
// know whether the Register button should be shown (allow_signups) and
// whether the post-register email-verification gate is active. The
// payload contains no sensitive fields.
package status

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/yackey-labs/yauth/middleware"
	"github.com/yackey-labs/yauth/plugin"
)

// Version is the static version reported by GET /status. It is exported
// so tests and embedders can override it.
var Version = "0.0.1"

type statusPlugin struct{}

// New constructs the status plugin.
func New() plugin.Plugin { return &statusPlugin{} }

// Name implements plugin.Plugin.
func (p *statusPlugin) Name() string { return "status" }

// Routes implements plugin.Plugin.
func (p *statusPlugin) Routes(host plugin.PluginHost, mux plugin.Router, api huma.API, prefix string) {
	mw := host.Middleware()

	// /status is admin-only — it reports operational metadata (registered
	// plugin names + version). Huma-native: a typed output guarded by
	// RequireAdminHuma, which writes RFC 9457 problem+json 401 (no-auth) /
	// 403 (non-admin) and short-circuits. The output body is byte-for-byte
	// the legacy handleStatus output (statusResponse). No StashHTTPHuma: the
	// handler needs no raw *http.Request, only host accessors.
	huma.Register(api, huma.Operation{
		OperationID: "get-status",
		Method:      http.MethodGet,
		Path:        prefix + "/status",
		Summary:     "Diagnostic status",
		Description: "Registered plugin names and the server version string. Admin-only.",
		Tags:        []string{"status"},
		Security:    []map[string][]string{{"sessionCookie": {}}},
		Middlewares: huma.Middlewares{middleware.RequireAdminHuma(api, mw)},
	}, func(_ context.Context, _ *statusInput) (*statusOutput, error) {
		return &statusOutput{Body: statusResponse{
			Plugins: host.PluginNames(),
			Version: Version,
		}}, nil
	})

	// /config is public — the SPA needs it before login (signups/email-verify
	// flags drive UI gating). Mirrors yauth's `core_public_routes` policy.
	//
	// Reference migration (huma-native phase 0): /config is the plugin's only
	// unauthenticated route, so it proves the no-auth huma path. The response
	// body is byte-for-byte the legacy handleConfig output (configResponse).
	huma.Register(api, huma.Operation{
		OperationID: "get-config",
		Method:      http.MethodGet,
		Path:        prefix + "/config",
		Summary:     "Public client config",
		Description: "Operator-toggled flags the SPA reads before login (signups, email-verify gating). Unauthenticated.",
		Tags:        []string{"status"},
		Security:    []map[string][]string{}, // explicitly public
	}, func(_ context.Context, _ *configInput) (*configOutput, error) {
		return &configOutput{Body: configResponse{
			AllowSignups:             host.AllowSignups(),
			RequireEmailVerification: false,
		}}, nil
	})
}

// statusInput has no fields — GET /status takes no parameters or body.
type statusInput struct{}

// statusOutput wraps the legacy statusResponse so huma emits exactly the
// same JSON object the net/http handler did.
type statusOutput struct {
	Body statusResponse
}

// configInput has no fields — GET /config takes no parameters or body.
type configInput struct{}

// configOutput wraps the legacy configResponse so huma emits exactly the
// same JSON object the net/http handler did.
type configOutput struct {
	Body configResponse
}
