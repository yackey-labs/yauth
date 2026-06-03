// Package humaerr provides a single huma-compatible error type that
// preserves yauth-go's historical wire contract for error responses:
//
//	{"error": {"code": "...", "message": "..."}}
//
// Every hand-written plugin handler emitted that envelope via a per-plugin
// writeError(w, status, code, message) helper. As routes migrate to
// huma-native serving (huma.Register typed handlers), handlers instead
// return an error value; huma marshals it through this type so the JSON
// response body is byte-for-byte identical to the legacy handlers. (The
// response Content-Type changes from "application/json; charset=utf-8" to
// huma's negotiated "application/json" — a migration-wide transport change,
// not a body change.)
//
// Two entry points keep the contract intact:
//
//   - Errf(status, code, message) is the 1:1 replacement for the old
//     writeError call — handlers return it to emit a specific code/message.
//   - Override (installed once at huma.API construction via
//     huma.NewError = humaerr.Override) makes huma's OWN built-in errors
//     (request-validation 422/400, content negotiation 406, etc.) marshal to
//     the same envelope, deriving the code from the HTTP status.
package humaerr

import (
	"encoding/json"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
)

// Error is a huma.StatusError whose JSON form is the canonical yauth-go
// {"error":{"code,message}} envelope. It implements json.Marshaler so the
// API's default JSON marshaler (and api.Marshal) renders exactly those
// bytes, regardless of any struct tags huma would otherwise apply.
type Error struct {
	Status  int    `json:"-"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// GetStatus implements huma.StatusError: the HTTP status code huma should
// send when this error is returned from a handler.
func (e *Error) GetStatus() int { return e.Status }

// Error implements the error interface. The message is the human-readable
// detail; the code is carried separately on the wire.
func (e *Error) Error() string { return e.Message }

// MarshalJSON renders the canonical envelope:
//
//	{"error":{"code":"<code>","message":"<message>"}}
func (e *Error) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Error errorBody `json:"error"`
	}{
		Error: errorBody{Code: e.Code, Message: e.Message},
	})
}

type errorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Errf builds a huma.StatusError carrying an explicit status, code, and
// message. It is the direct replacement for the legacy
// writeError(w, status, code, message): a migrated handler returns
// humaerr.Errf(http.StatusNotFound, "NOT_FOUND", "user not found") in place
// of writeError(w, http.StatusNotFound, "NOT_FOUND", "user not found").
func Errf(status int, code, message string) huma.StatusError {
	return &Error{Status: status, Code: code, Message: message}
}

// Override is the replacement for huma.NewError. Installing it once at API
// construction (huma.NewError = humaerr.Override) makes huma's built-in
// errors — request validation (422), malformed body (400), content
// negotiation (406), and any internal 500 — marshal to the same
// {"error":{code,message}} envelope as the hand-written handlers, instead of
// huma's default {title,status,detail,errors} RFC 7807 shape.
//
// The code is derived from the HTTP status to match the strings the
// codebase already used in its writeError calls.
func Override(status int, msg string, _ ...error) huma.StatusError {
	return &Error{Status: status, Code: codeForStatus(status), Message: msg}
}

// codeForStatus maps an HTTP status to the lowercase code string yauth-go
// uses for framework-generated (non-handler) errors. These match the codes
// the codebase already emits for the corresponding conditions.
func codeForStatus(status int) string {
	switch status {
	case http.StatusBadRequest, http.StatusUnprocessableEntity:
		return "invalid_request"
	case http.StatusUnauthorized:
		return "unauthorized"
	case http.StatusForbidden:
		return "forbidden"
	case http.StatusNotFound:
		return "not_found"
	case http.StatusConflict:
		return "conflict"
	case http.StatusInternalServerError:
		return "internal_error"
	default:
		if status >= 500 {
			return "internal_error"
		}
		return "invalid_request"
	}
}
