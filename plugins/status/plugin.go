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
	"net/http"

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
func (p *statusPlugin) Routes(host plugin.PluginHost, mux plugin.Router, prefix string) {
	mw := host.Middleware()
	mux.Handle("GET "+prefix+"/status", mw.RequireAdmin(http.HandlerFunc(p.handleStatus(host))))
	// /config is public — the SPA needs it before login (signups/email-verify
	// flags drive UI gating). Mirrors yauth's `core_public_routes` policy.
	mux.HandleFunc("GET "+prefix+"/config", p.handleConfig(host))
}
