package status

import (
	"encoding/json"
	"net/http"

	"github.com/yackey-labs/yauth-go/plugin"
)

type statusResponse struct {
	Plugins []string `json:"plugins"`
	Version string   `json:"version"`
}

func (p *statusPlugin) handleStatus(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(statusResponse{
			Plugins: host.PluginNames(),
			Version: Version,
		})
	}
}

// configResponse mirrors the Rust shape: only the operator-toggled
// flags clients need to render their UI. Operational metadata (plugins,
// version, base_url) is exposed via GET /status, not here.
type configResponse struct {
	AllowSignups             bool `json:"allow_signups"`
	RequireEmailVerification bool `json:"require_email_verification"`
}

func (p *statusPlugin) handleConfig(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(configResponse{
			AllowSignups:             host.AllowSignups(),
			RequireEmailVerification: false,
		})
	}
}
