package oauth2server

import (
	"encoding/json"
	"net/http"
)

// oauthError is the RFC 6749 §5.2 error response shape.
type oauthError struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// writeOAuthError emits an RFC 6749 error response. The standard
// status code mapping is:
//
//	invalid_request           → 400
//	invalid_client            → 401 (with WWW-Authenticate)
//	invalid_grant             → 400
//	unauthorized_client       → 400
//	unsupported_grant_type    → 400
//	invalid_scope             → 400
//	access_denied             → 400
//	server_error              → 500
//	authorization_pending     → 400 (RFC 8628)
//	slow_down                 → 400 (RFC 8628)
//	expired_token             → 400 (RFC 8628)
func writeOAuthError(w http.ResponseWriter, code, description string) {
	status := statusFor(code)
	if code == "invalid_client" {
		w.Header().Set("WWW-Authenticate", `Basic realm="oauth2"`)
	}
	writeJSON(w, status, oauthError{Error: code, ErrorDescription: description})
}

func statusFor(code string) int {
	switch code {
	case "invalid_client":
		return http.StatusUnauthorized
	case "server_error":
		return http.StatusInternalServerError
	default:
		return http.StatusBadRequest
	}
}

// writeJSON writes v as application/json with the given status. It
// also sets Cache-Control: no-store as RFC 6749 §5.1 requires.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
