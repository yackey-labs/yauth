package oauth2server_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth/domain"
)

// converted_routes_test.go exercises the JSON admin/CRUD write-ops that were
// migrated from func-body streaming to native huma typed Body
// (POST/PATCH /oauth2/clients, POST /oauth2/clients/{id}/groups, .../roles,
// POST /oauth2/consent). It proves the requirements the rest of the suite did
// not cover at the HTTP layer:
//
//   - unknown/malformed JSON body → native 422 (additionalProperties:false),
//   - business errors keep their legacy status (404 / 400) as problem+json,
//   - success statuses (201 / 200 / 204) are preserved,
//   - admin/auth gating still applies.

// adminReq sends an arbitrary-method JSON request with the admin session
// cookie and returns the status code (body discarded). It never fatals on a
// non-2xx so callers can assert the exact status.
func (h *harness) adminReq(t *testing.T, method, path, adminCookie, body string) int {
	t.Helper()
	req, _ := http.NewRequest(method, h.srv.URL+path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	req.AddCookie(&http.Cookie{Name: "yauth_session", Value: adminCookie})
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer res.Body.Close()
	return res.StatusCode
}

// TestConvertedCreateClient_UnknownField_422 proves the native typed Body's
// additionalProperties:false is actually wired: an unknown field is rejected
// with 422 (huma validation), not silently accepted.
func TestConvertedCreateClient_UnknownField_422(t *testing.T) {
	h := newHarness(t)
	_, adminCookie := h.seedUser(t, "admin@idp.test", "admin")

	// Valid required fields + one unknown field.
	body := `{"name":"x","redirect_uris":[],"grant_types":["client_credentials"],"scopes":["read"],"is_public":false,"bogus_field":"nope"}`
	st := h.adminReq(t, http.MethodPost, "/api/auth/oauth2/clients", adminCookie, body)
	if st != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 on unknown field, got %d", st)
	}
}

// TestConvertedCreateClient_MalformedJSON_Native proves a malformed (un-
// parseable) JSON body is rejected by huma's native error path. huma splits
// the body-error space: a body that fails to JSON-parse → 400; a body that
// parses but violates the schema (unknown field, wrong type) → 422
// (see TestConvertedCreateClient_UnknownField_422). Either way the bridged
// handler's hand-rolled RFC-6749 invalid_request body is gone — huma owns the
// rejection. We assert the request is rejected with one of those native codes
// rather than fabricating a 422 huma does not emit for unparseable input.
func TestConvertedCreateClient_MalformedJSON_Native(t *testing.T) {
	h := newHarness(t)
	_, adminCookie := h.seedUser(t, "admin@idp.test", "admin")

	st := h.adminReq(t, http.MethodPost, "/api/auth/oauth2/clients", adminCookie, `{not json`)
	if st != http.StatusBadRequest && st != http.StatusUnprocessableEntity {
		t.Fatalf("expected native 400/422 on malformed JSON, got %d", st)
	}
}

// TestConvertedCreateClient_RequiresAdmin proves the admin gate survives the
// conversion (no admin cookie → not 201).
func TestConvertedCreateClient_RequiresAdmin(t *testing.T) {
	h := newHarness(t)
	_, userCookie := h.seedUser(t, "user@idp.test", "user")

	body := `{"name":"x","redirect_uris":[],"grant_types":["client_credentials"],"scopes":["read"],"is_public":false}`
	st := h.adminReq(t, http.MethodPost, "/api/auth/oauth2/clients", userCookie, body)
	if st == http.StatusCreated {
		t.Fatalf("non-admin must not create a client, got 201")
	}
	if st != http.StatusForbidden && st != http.StatusUnauthorized {
		t.Fatalf("expected 401/403 for non-admin, got %d", st)
	}
}

// TestConvertedPatchClient_HTTP exercises PATCH /oauth2/clients/{id} over HTTP:
// a valid patch (ban) → 200, and an unknown field → 422.
func TestConvertedPatchClient_HTTP(t *testing.T) {
	h := newHarness(t)
	_, adminCookie := h.seedUser(t, "admin@idp.test", "admin")
	body := `{"name":"p","redirect_uris":[],"grant_types":["client_credentials"],"scopes":["read"],"is_public":false}`
	clientID, _, _ := h.createClient(t, adminCookie, body)

	// Valid PATCH (ban) → 200.
	st := h.adminReq(t, http.MethodPatch, "/api/auth/oauth2/clients/"+clientID, adminCookie, `{"banned":true,"banned_reason":"x"}`)
	if st != http.StatusOK {
		t.Fatalf("valid patch: expected 200, got %d", st)
	}

	// Unknown field → 422.
	st = h.adminReq(t, http.MethodPatch, "/api/auth/oauth2/clients/"+clientID, adminCookie, `{"banned":false,"surprise":1}`)
	if st != http.StatusUnprocessableEntity {
		t.Fatalf("patch unknown field: expected 422, got %d", st)
	}
}

// TestConvertedAssignGroup_HTTP exercises POST /oauth2/clients/{id}/groups over
// HTTP: success → 204, unknown body field → 422, bad client → 404, missing
// group_id → 400, unknown group → 404.
func TestConvertedAssignGroup_HTTP(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	now := time.Now().UTC()
	_, adminCookie := h.seedUser(t, "admin@idp.test", "admin")

	org, err := h.repo.CreateOrganization(ctx, domain.NewOrganization{
		ID: uuid.NewString(), Name: "O", Slug: "o-" + uuid.NewString()[:8], CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("create org: %v", err)
	}
	g, err := h.repo.CreateGroup(ctx, domain.NewGroup{
		ID: uuid.NewString(), OrganizationID: org.ID, Name: "Eng", CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("create group: %v", err)
	}

	body := `{"name":"ag","redirect_uris":["https://app.example/callback"],"grant_types":["authorization_code"],"scopes":["openid"],"is_public":false,"token_endpoint_auth_method":"client_secret_post"}`
	clientID, _, _ := h.createClient(t, adminCookie, body)

	path := "/api/auth/oauth2/clients/" + clientID + "/groups"

	// success → 204
	if st := h.adminReq(t, http.MethodPost, path, adminCookie, `{"group_id":"`+g.ID+`"}`); st != http.StatusNoContent {
		t.Fatalf("assign group: expected 204, got %d", st)
	}
	// unknown body field → 422
	if st := h.adminReq(t, http.MethodPost, path, adminCookie, `{"group_id":"`+g.ID+`","x":1}`); st != http.StatusUnprocessableEntity {
		t.Fatalf("assign group unknown field: expected 422, got %d", st)
	}
	// missing group_id → 400
	if st := h.adminReq(t, http.MethodPost, path, adminCookie, `{}`); st != http.StatusBadRequest {
		t.Fatalf("assign group missing group_id: expected 400, got %d", st)
	}
	// unknown group → 404
	if st := h.adminReq(t, http.MethodPost, path, adminCookie, `{"group_id":"`+uuid.NewString()+`"}`); st != http.StatusNotFound {
		t.Fatalf("assign group unknown group: expected 404, got %d", st)
	}
	// bad client → 404
	badPath := "/api/auth/oauth2/clients/" + uuid.NewString() + "/groups"
	if st := h.adminReq(t, http.MethodPost, badPath, adminCookie, `{"group_id":"`+g.ID+`"}`); st != http.StatusNotFound {
		t.Fatalf("assign group bad client: expected 404, got %d", st)
	}
}

// TestConvertedAssignRole_HTTP exercises POST /oauth2/clients/{id}/roles over
// HTTP: success → 204, unknown body field → 422, empty role → 400, both
// principals set → 400, bad client → 404.
func TestConvertedAssignRole_HTTP(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	now := time.Now().UTC()
	_, adminCookie := h.seedUser(t, "admin@idp.test", "admin")

	uid, _ := h.seedUser(t, "roleuser@idp.test", "user")

	body := `{"name":"ar","redirect_uris":["https://app.example/callback"],"grant_types":["authorization_code"],"scopes":["openid"],"is_public":false,"token_endpoint_auth_method":"client_secret_post"}`
	clientID, _, _ := h.createClient(t, adminCookie, body)
	_ = ctx
	_ = now

	path := "/api/auth/oauth2/clients/" + clientID + "/roles"

	// success → 204 (role assigned to a user)
	if st := h.adminReq(t, http.MethodPost, path, adminCookie, `{"role":"owner","user_id":"`+uid+`"}`); st != http.StatusNoContent {
		t.Fatalf("assign role: expected 204, got %d", st)
	}
	// unknown body field → 422
	if st := h.adminReq(t, http.MethodPost, path, adminCookie, `{"role":"x","user_id":"`+uid+`","z":1}`); st != http.StatusUnprocessableEntity {
		t.Fatalf("assign role unknown field: expected 422, got %d", st)
	}
	// empty role → 400
	if st := h.adminReq(t, http.MethodPost, path, adminCookie, `{"role":"   ","user_id":"`+uid+`"}`); st != http.StatusBadRequest {
		t.Fatalf("assign role empty role: expected 400, got %d", st)
	}
	// both principals → 400
	if st := h.adminReq(t, http.MethodPost, path, adminCookie, `{"role":"x","user_id":"`+uid+`","group_id":"`+uuid.NewString()+`"}`); st != http.StatusBadRequest {
		t.Fatalf("assign role both principals: expected 400, got %d", st)
	}
	// bad client → 404
	badPath := "/api/auth/oauth2/clients/" + uuid.NewString() + "/roles"
	if st := h.adminReq(t, http.MethodPost, badPath, adminCookie, `{"role":"x","user_id":"`+uid+`"}`); st != http.StatusNotFound {
		t.Fatalf("assign role bad client: expected 404, got %d", st)
	}
}

// TestConvertedConsent_UnknownField_422 proves the consent route's native
// typed Body rejects unknown fields with 422 while remaining session-gated for
// a regular (non-admin) end-user.
func TestConvertedConsent_UnknownField_422(t *testing.T) {
	h := newHarness(t)
	_, userCookie := h.seedUser(t, "consent-user@idp.test", "user")

	req, _ := http.NewRequest(http.MethodPost, h.srv.URL+"/api/auth/oauth2/consent",
		strings.NewReader(`{"request_id":"x","csrf_token":"y","approved":true,"bogus":1}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "yauth_session", Value: userCookie})
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("consent: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("consent unknown field: expected 422, got %d", res.StatusCode)
	}
}

// TestConvertedCreateClient_ResponseShape confirms the 201 success body keeps
// its exact wrapper ({client:{...}, client_secret}) after the conversion.
func TestConvertedCreateClient_ResponseShape(t *testing.T) {
	h := newHarness(t)
	_, adminCookie := h.seedUser(t, "admin@idp.test", "admin")

	body := `{"name":"shape","redirect_uris":[],"grant_types":["client_credentials"],"scopes":["read"],"is_public":false,"token_endpoint_auth_method":"client_secret_basic"}`
	req, _ := http.NewRequest(http.MethodPost, h.srv.URL+"/api/auth/oauth2/clients", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "yauth_session", Value: adminCookie})
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("create: expected 201, got %d", res.StatusCode)
	}
	var out map[string]json.RawMessage
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := out["client"]; !ok {
		t.Fatalf("response missing 'client' wrapper: keys=%v", out)
	}
	if _, ok := out["client_secret"]; !ok {
		t.Fatalf("confidential client response missing 'client_secret': keys=%v", out)
	}
}
