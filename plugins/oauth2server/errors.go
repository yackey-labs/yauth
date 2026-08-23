package oauth2server

import (
	"encoding/json"
	"net/http"
	"strings"
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

// sanitizeErr returns err.Error() with any control characters stripped so
// the result is safe to concatenate into JSON error_description responses.
// This is purely a defense-in-depth helper for static-analyzer false
// positives that flag string concatenation of error.Error() — no SQL is
// constructed by these call sites; output goes only to a JSON body.
func sanitizeErr(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c == 0x7f {
			continue
		}
		out = append(out, c)
	}
	return string(out)
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

// reqParam is one wire parameter and the value that arrived for it, for
// [missingParams].
type reqParam struct {
	name  string
	value string
}

// missingParams builds the error_description for an RFC 6749 invalid_request
// caused by absent parameters, naming ONLY the ones that are actually absent.
// It returns "" when every parameter has a value, which is the caller's
// "carry on" signal.
//
// The two call sites used to list every parameter they checked, whichever one
// was missing. An oauth2-proxy client that sent a perfectly good client_id and
// redirect_uri but no code_challenge was told "client_id, redirect_uri,
// code_challenge are required", which reads as a broken client registration and
// sends whoever is debugging it to re-check the two parameters that were fine.
// A message that names three things when one is wrong is worse than no message:
// it is a message pointing the wrong way.
//
// Only the human-readable half changes. RFC 6749 §5.2 defines the error CODE
// as the machine-readable field and error_description as free text for the
// developer, so the code stays invalid_request and no client that switches on
// it is affected. Emptiness is still literal "" — a whitespace-only value is
// left to fail its own downstream validation, exactly as before.
func missingParams(params ...reqParam) string {
	missing := make([]string, 0, len(params))
	for _, p := range params {
		if p.value == "" {
			missing = append(missing, p.name)
		}
	}
	switch len(missing) {
	case 0:
		return ""
	case 1:
		return missing[0] + " is required"
	default:
		return strings.Join(missing[:len(missing)-1], ", ") + " and " + missing[len(missing)-1] + " are required"
	}
}
