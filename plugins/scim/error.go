package scim

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/yackey-labs/yauth-go/yautherr"
)

// ScimContentType is the content type IdPs expect on a SCIM response.
// RFC 7644 §3.8.
const ScimContentType = "application/scim+json"

// ScimResponseError is the SCIM-shaped error envelope a handler returns
// when it cannot complete a request. The handler MUST write it via
// writeScimError so the response carries the correct content type, HTTP
// status, and RFC 7644 §3.12 body shape.
type ScimResponseError struct {
	Status int           // HTTP status code
	Body   ScimErrorBody // RFC 7644 §3.12 envelope
}

// Error implements error so handlers can return *ScimResponseError as
// the error result of a step.
func (e *ScimResponseError) Error() string {
	return e.Body.Detail
}

// newScimErr is a small constructor used by the shortcut helpers below.
func newScimErr(status int, scimType, detail string) *ScimResponseError {
	return &ScimResponseError{
		Status: status,
		Body:   NewScimErrorBody(status, scimType, detail),
	}
}

// BadRequest returns a 400 invalidSyntax SCIM error.
func BadRequest(detail string) *ScimResponseError {
	return newScimErr(http.StatusBadRequest, "invalidSyntax", detail)
}

// InvalidFilter returns a 400 invalidFilter SCIM error.
func InvalidFilter(detail string) *ScimResponseError {
	return newScimErr(http.StatusBadRequest, "invalidFilter", detail)
}

// Unauthorized returns a 401 invalidCredentials SCIM error.
func Unauthorized(detail string) *ScimResponseError {
	return newScimErr(http.StatusUnauthorized, "invalidCredentials", detail)
}

// Forbidden returns a 403 invalidValue SCIM error.
func Forbidden(detail string) *ScimResponseError {
	return newScimErr(http.StatusForbidden, "invalidValue", detail)
}

// NotFound returns a 404 noTarget SCIM error.
func NotFound(detail string) *ScimResponseError {
	return newScimErr(http.StatusNotFound, "noTarget", detail)
}

// Conflict returns a 409 uniqueness SCIM error.
func Conflict(detail string) *ScimResponseError {
	return newScimErr(http.StatusConflict, "uniqueness", detail)
}

// InternalError returns a 500 with a deliberately short detail. We do
// not surface internal trace/error text — IdPs don't act on it and the
// detail might leak storage paths.
func InternalError() *ScimResponseError {
	return newScimErr(http.StatusInternalServerError, "", "internal error")
}

// repoToScim maps a repo-layer error to a SCIM response error. Unknown
// errors collapse to a generic 500.
func repoToScim(err error) *ScimResponseError {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, yautherr.ErrNotFound):
		return NotFound("resource not found")
	case errors.Is(err, yautherr.ErrConflict):
		return Conflict(err.Error())
	}
	return InternalError()
}

// writeScimJSON serialises body as JSON with the SCIM content type. On
// serialise failure the response is replaced with a generic 500.
func writeScimJSON(w http.ResponseWriter, status int, body any) {
	buf, err := json.Marshal(body)
	if err != nil {
		writeScimError(w, InternalError())
		return
	}
	w.Header().Set("Content-Type", ScimContentType)
	w.WriteHeader(status)
	_, _ = w.Write(buf)
}

// writeScimError writes a SCIM error response with the correct content
// type and status.
func writeScimError(w http.ResponseWriter, e *ScimResponseError) {
	buf, err := json.Marshal(e.Body)
	if err != nil {
		// Last resort — write a minimal SCIM error.
		w.Header().Set("Content-Type", ScimContentType)
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:Error"],"status":"500"}`))
		return
	}
	w.Header().Set("Content-Type", ScimContentType)
	w.WriteHeader(e.Status)
	_, _ = w.Write(buf)
}

// writeScimNoContent writes a 204 with the SCIM content type and no
// body. Used by DELETE handlers (RFC 7644 §3.6).
func writeScimNoContent(w http.ResponseWriter) {
	w.Header().Set("Content-Type", ScimContentType)
	w.WriteHeader(http.StatusNoContent)
}
