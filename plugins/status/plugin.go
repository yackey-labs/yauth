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

	"github.com/yackey-labs/yauth-go/plugin"
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
	mux.Handle("GET "+prefix+"/status", mw.RequireAdmin(http.HandlerFunc(p.handleStatus(host))))

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

// configInput has no fields — GET /config takes no parameters or body.
type configInput struct{}

// configOutput wraps the legacy configResponse so huma emits exactly the
// same JSON object the net/http handler did.
type configOutput struct {
	Body configResponse
}
