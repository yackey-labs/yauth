package status

// statusResponse is the GET /status body: registered plugin names and the
// server version string. GET /status is served huma-native (see plugin.go);
// this struct is the response body huma marshals.
type statusResponse struct {
	Plugins []string `json:"plugins"`
	Version string   `json:"version"`
}

// configResponse mirrors the Rust shape: only the operator-toggled
// flags clients need to render their UI. Operational metadata (plugins,
// version, base_url) is exposed via GET /status, not here.
//
// GET /config is served huma-native (see plugin.go); this struct is the
// response body huma marshals.
type configResponse struct {
	AllowSignups             bool `json:"allow_signups"`
	RequireEmailVerification bool `json:"require_email_verification"`
}
