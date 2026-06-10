package admin_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/yackey-labs/yauth/auth"
)

func TestAdmin_CreateUser(t *testing.T) {
	env := newEnv(t)
	defer env.stop()

	admin := env.seedUser(t, "admin@example.com", "admin")
	tok := env.issueSession(t, admin.ID)

	// Generated temp password: returned once, credential usable, flags set.
	res := env.do(t, http.MethodPost, "/api/auth/admin/users", tok, map[string]any{
		"email":        "New.Hire@Example.com", // normalized to lowercase
		"display_name": "New Hire",
	})
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("create: %d (%s)", res.StatusCode, drain(res))
	}
	var out struct {
		User struct {
			ID                 string  `json:"id"`
			Email              string  `json:"email"`
			DisplayName        *string `json:"display_name"`
			Role               string  `json:"role"`
			MustChangePassword bool    `json:"must_change_password"`
		} `json:"user"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	res.Body.Close()
	if out.User.Email != "new.hire@example.com" || out.User.Role != "user" || !out.User.MustChangePassword {
		t.Fatalf("user: %+v", out.User)
	}
	if out.User.DisplayName == nil || *out.User.DisplayName != "New Hire" {
		t.Fatalf("display_name: %v", out.User.DisplayName)
	}
	if len(out.Password) < 20 {
		t.Fatalf("expected generated temp password, got %q", out.Password)
	}
	// The generated credential actually verifies against the stored hash.
	pw, err := env.repo.GetPasswordByUserID(context.Background(), out.User.ID)
	if err != nil || pw == nil {
		t.Fatalf("stored password: %+v err=%v", pw, err)
	}
	if ok, err := auth.VerifyPassword(out.Password, pw.PasswordHash); err != nil || !ok {
		t.Fatalf("temp password does not verify: ok=%v err=%v", ok, err)
	}

	// Duplicate email → 409.
	res = env.do(t, http.MethodPost, "/api/auth/admin/users", tok, map[string]any{
		"email": "new.hire@example.com",
	})
	if res.StatusCode != http.StatusConflict {
		t.Fatalf("duplicate: expected 409, got %d", res.StatusCode)
	}
	res.Body.Close()

	// Operator-provided password: never echoed.
	res = env.do(t, http.MethodPost, "/api/auth/admin/users", tok, map[string]any{
		"email": "second@example.com", "password": "Operator-Chosen-1", "role": "admin",
		"must_change_password": false,
	})
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("create2: %d (%s)", res.StatusCode, drain(res))
	}
	var out2 struct {
		User struct {
			Role               string `json:"role"`
			MustChangePassword bool   `json:"must_change_password"`
		} `json:"user"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out2); err != nil {
		t.Fatalf("decode2: %v", err)
	}
	res.Body.Close()
	if out2.Password != "" {
		t.Fatal("operator-provided password must not be echoed")
	}
	if out2.User.Role != "admin" || out2.User.MustChangePassword {
		t.Fatalf("user2: %+v", out2.User)
	}

	// Non-admin caller → 403.
	plain := env.seedUser(t, "plain@example.com", "user")
	ptok := env.issueSession(t, plain.ID)
	res = env.do(t, http.MethodPost, "/api/auth/admin/users", ptok, map[string]any{
		"email": "nope@example.com",
	})
	if res.StatusCode != http.StatusForbidden && res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("non-admin: expected 401/403, got %d", res.StatusCode)
	}
	res.Body.Close()
}
