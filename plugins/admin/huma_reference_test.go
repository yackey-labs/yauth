package admin_test

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth-go/domain"
)

// errorEnvelope is the canonical yauth-go error wire shape
// ({"error":{code,message}}) the migrated huma routes must preserve.
type errorEnvelope struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// TestHumaRef_AdminGetUser_AuthMatrix proves the huma-migrated
// GET /admin/users/{id} reference route end-to-end: no-auth → 401 envelope,
// non-admin → 403 envelope, admin → 200 with the full lifecycle-bearing
// userJSON body.
func TestHumaRef_AdminGetUser_AuthMatrix(t *testing.T) {
	env := newEnv(t)
	defer env.stop()

	admin := env.seedUser(t, "admin@example.com", "admin")
	// Seed a target with lifecycle state set so we can assert those fields
	// survive the typed-output migration.
	now := time.Now().UTC()
	susReason := "offboarded"
	target, err := env.repo.CreateUser(t.Context(), domain.NewUser{
		ID:        uuid.NewString(),
		Email:     "target@example.com",
		Role:      "user",
		CreatedAt: now,
		UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("seed target: %v", err)
	}
	suspendedAt := now
	suspendedAtP := &suspendedAt
	susReasonP := &susReason
	if _, err := env.repo.UpdateUser(t.Context(), target.ID, domain.UpdateUser{
		SuspendedAt:     &suspendedAtP,
		SuspendedReason: &susReasonP,
		UpdatedAt:       &now,
	}); err != nil {
		t.Fatalf("set lifecycle: %v", err)
	}

	adminTok := env.issueSession(t, admin.ID)
	path := "/api/auth/admin/users/" + target.ID

	// (a) no auth → 401 + {"error":{"code":"unauthorized",...}}
	res := env.do(t, http.MethodGet, path, "", nil)
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no-auth: expected 401, got %d (%s)", res.StatusCode, drain(res))
	}
	var env401 errorEnvelope
	if err := json.NewDecoder(res.Body).Decode(&env401); err != nil {
		t.Fatalf("no-auth: decode envelope: %v", err)
	}
	res.Body.Close()
	if env401.Error.Code != "unauthorized" {
		t.Fatalf("no-auth: expected code=unauthorized, got %q", env401.Error.Code)
	}

	// (b) non-admin → 403 + {"error":{"code":"forbidden",...}}
	regular := env.seedUser(t, "regular@example.com", "user")
	regTok := env.issueSession(t, regular.ID)
	res = env.do(t, http.MethodGet, path, regTok, nil)
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("non-admin: expected 403, got %d (%s)", res.StatusCode, drain(res))
	}
	var env403 errorEnvelope
	if err := json.NewDecoder(res.Body).Decode(&env403); err != nil {
		t.Fatalf("non-admin: decode envelope: %v", err)
	}
	res.Body.Close()
	if env403.Error.Code != "forbidden" {
		t.Fatalf("non-admin: expected code=forbidden, got %q", env403.Error.Code)
	}

	// (c) admin → 200 + full user JSON incl. lifecycle fields.
	res = env.do(t, http.MethodGet, path, adminTok, nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("admin: expected 200, got %d (%s)", res.StatusCode, drain(res))
	}
	var body map[string]any
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatalf("admin: decode body: %v", err)
	}
	res.Body.Close()
	if body["id"] != target.ID || body["email"] != "target@example.com" {
		t.Fatalf("admin: id/email mismatch: %+v", body)
	}
	if body["suspended"] != true {
		t.Fatalf("admin: expected suspended=true, got %v", body["suspended"])
	}
	if body["suspended_reason"] != susReason {
		t.Fatalf("admin: expected suspended_reason=%q, got %v", susReason, body["suspended_reason"])
	}
	// Lifecycle field keys must be present in the typed output.
	for _, k := range []string{"role", "banned", "email_verified", "created_at", "updated_at", "suspended_at"} {
		if _, ok := body[k]; !ok {
			t.Fatalf("admin: missing field %q in body %+v", k, body)
		}
	}
	// No huma $schema leakage in the body.
	if _, ok := body["$schema"]; ok {
		t.Fatalf("admin: unexpected $schema field in body (transformer leaked)")
	}

	// (d) admin, unknown id → 404 + {"error":{"code":"NOT_FOUND",...}}.
	res = env.do(t, http.MethodGet, "/api/auth/admin/users/"+uuid.NewString(), adminTok, nil)
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("not-found: expected 404, got %d (%s)", res.StatusCode, drain(res))
	}
	var env404 errorEnvelope
	if err := json.NewDecoder(res.Body).Decode(&env404); err != nil {
		t.Fatalf("not-found: decode envelope: %v", err)
	}
	res.Body.Close()
	if env404.Error.Code != "NOT_FOUND" {
		t.Fatalf("not-found: expected code=NOT_FOUND (handler-preserved), got %q", env404.Error.Code)
	}
}
