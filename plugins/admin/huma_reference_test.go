package admin_test

import (
	"encoding/json"
	"io"
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

// TestHuma_AdminRoutes_AuthMatrix proves the full huma-native admin migration
// across three route shapes — GET+query (list users), POST+body→200 (ban), and
// DELETE→204 (delete user) — each enforcing the auth gate (no-auth→401,
// non-admin→403, admin→success) and preserving the exact success status code.
func TestHuma_AdminRoutes_AuthMatrix(t *testing.T) {
	env := newEnv(t)
	defer env.stop()

	admin := env.seedUser(t, "admin@example.com", "admin")
	adminTok := env.issueSession(t, admin.ID)
	regular := env.seedUser(t, "regular@example.com", "user")
	regTok := env.issueSession(t, regular.ID)

	// matrix runs the three-way gate check for one route, then invokes onAdmin
	// to assert the route-specific success behavior with admin creds.
	matrix := func(name, method, path string, body any, onAdmin func(t *testing.T)) {
		t.Run(name, func(t *testing.T) {
			// no auth → 401
			res := env.do(t, method, path, "", body)
			if res.StatusCode != http.StatusUnauthorized {
				t.Fatalf("no-auth: want 401, got %d (%s)", res.StatusCode, drain(res))
			}
			res.Body.Close()
			// non-admin → 403
			res = env.do(t, method, path, regTok, body)
			if res.StatusCode != http.StatusForbidden {
				t.Fatalf("non-admin: want 403, got %d (%s)", res.StatusCode, drain(res))
			}
			res.Body.Close()
			// admin → route-specific success
			onAdmin(t)
		})
	}

	// GET /admin/users (+query) → 200 with the `users` envelope.
	matrix("list-users", http.MethodGet, "/api/auth/admin/users?search=&limit=10", nil, func(t *testing.T) {
		res := env.do(t, http.MethodGet, "/api/auth/admin/users?limit=10", adminTok, nil)
		if res.StatusCode != http.StatusOK {
			t.Fatalf("admin list: want 200, got %d (%s)", res.StatusCode, drain(res))
		}
		var body struct {
			Users   []map[string]any `json:"users"`
			PerPage int              `json:"per_page"`
		}
		if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
			t.Fatalf("admin list: decode: %v", err)
		}
		res.Body.Close()
		if body.PerPage != 10 {
			t.Fatalf("admin list: want per_page=10 (query parsed), got %d", body.PerPage)
		}
		if len(body.Users) < 2 {
			t.Fatalf("admin list: want >=2 users, got %d", len(body.Users))
		}
	})

	// POST /admin/users/{id}/ban (+body) → 200 with the banned userJSON.
	banTarget := env.seedUser(t, "ban-target@example.com", "user")
	matrix("ban-user", http.MethodPost, "/api/auth/admin/users/"+banTarget.ID+"/ban",
		map[string]any{"reason": "policy"}, func(t *testing.T) {
			res := env.do(t, http.MethodPost, "/api/auth/admin/users/"+banTarget.ID+"/ban", adminTok,
				map[string]any{"reason": "policy"})
			if res.StatusCode != http.StatusOK {
				t.Fatalf("admin ban: want 200, got %d (%s)", res.StatusCode, drain(res))
			}
			var body map[string]any
			if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
				t.Fatalf("admin ban: decode: %v", err)
			}
			res.Body.Close()
			if body["banned"] != true {
				t.Fatalf("admin ban: want banned=true, got %v", body["banned"])
			}
		})

	// POST /admin/users/{id}/ban with no reason → 400 INVALID_REQUEST
	// (strict body decode preserved through the raw-request bridge).
	t.Run("ban-no-reason-400", func(t *testing.T) {
		res := env.do(t, http.MethodPost, "/api/auth/admin/users/"+banTarget.ID+"/ban", adminTok,
			map[string]any{})
		if res.StatusCode != http.StatusBadRequest {
			t.Fatalf("ban no-reason: want 400, got %d (%s)", res.StatusCode, drain(res))
		}
		var e errorEnvelope
		if err := json.NewDecoder(res.Body).Decode(&e); err != nil {
			t.Fatalf("ban no-reason: decode: %v", err)
		}
		res.Body.Close()
		if e.Error.Code != "INVALID_REQUEST" {
			t.Fatalf("ban no-reason: want code=INVALID_REQUEST, got %q", e.Error.Code)
		}
	})

	// DELETE /admin/users/{id} → 204 no body.
	delTarget := env.seedUser(t, "del-target@example.com", "user")
	matrix("delete-user", http.MethodDelete, "/api/auth/admin/users/"+delTarget.ID, nil, func(t *testing.T) {
		res := env.do(t, http.MethodDelete, "/api/auth/admin/users/"+delTarget.ID, adminTok, nil)
		if res.StatusCode != http.StatusNoContent {
			t.Fatalf("admin delete: want 204, got %d (%s)", res.StatusCode, drain(res))
		}
		b, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if len(b) != 0 {
			t.Fatalf("admin delete: want empty body, got %q", string(b))
		}
	})
}
