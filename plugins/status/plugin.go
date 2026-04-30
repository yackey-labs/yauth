// Package status implements a tiny admin-only diagnostic plugin that
// reports the names of every plugin currently registered on the host
// along with a static version string.
//
// Routes registered by Plugin.Routes (relative to the prefix passed in):
//
//	GET {prefix}/status   admin-only — returns {plugins: [...names], version: "..."}
package status

import (
	"net/http"

	"github.com/yackey-labs/yauth-go/plugin"
)

// Version is the static version reported by GET /status. It is exported
// so tests and embedders can override it. The MVP value is "go-port-mvp".
var Version = "go-port-mvp"

type statusPlugin struct{}

// New constructs the status plugin.
func New() plugin.Plugin { return &statusPlugin{} }

// Name implements plugin.Plugin.
func (p *statusPlugin) Name() string { return "status" }

// Routes implements plugin.Plugin.
func (p *statusPlugin) Routes(host plugin.PluginHost, mux *http.ServeMux, prefix string) {
	mw := host.Middleware()
	mux.Handle("GET "+prefix+"/status", mw.RequireAdmin(http.HandlerFunc(p.handleStatus(host))))
}
