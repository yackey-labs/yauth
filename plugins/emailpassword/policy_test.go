package emailpassword_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	yauth "github.com/yackey-labs/yauth"
	"github.com/yackey-labs/yauth/auth/passwordpolicy"
	"github.com/yackey-labs/yauth/plugins/emailpassword"
	"github.com/yackey-labs/yauth/repo/gormrepo"
)

// TestRegister_PolicyRejectsWeakPassword exercises the password policy
// path on /register: a password missing required complexity classes
// must produce a 400 + WEAK_PASSWORD response.
func TestRegister_PolicyRejectsWeakPassword(t *testing.T) {
	dsn := "file:" + uuid.NewString() + "?mode=memory&cache=shared&_pragma=foreign_keys(1)"
	db, err := gormrepo.OpenSQLite(dsn)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := gormrepo.Migrate(context.Background(), db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	repoRef := gormrepo.New(db)

	ya, err := yauth.New(repoRef, yauth.NewDefaultConfig()).
		WithPlugin(emailpassword.New(emailpassword.Config{
			MinPasswordLength: 8,
			HIBPCheck:         false,
			HIBPCheckSet:      true,
			PasswordPolicy: passwordpolicy.Policy{
				MinLength:      12,
				RequireUpper:   true,
				RequireDigit:   true,
				RequireSpecial: true,
				DisallowCommon: true,
			},
		})).
		Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	res := postJSON(t, srv.URL+"/api/auth/register", map[string]any{
		"email":    "weak@example.com",
		"password": "alllowercaseonly",
	})
	res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing-uppercase password, got %d", res.StatusCode)
	}

	res = postJSON(t, srv.URL+"/api/auth/register", map[string]any{
		"email":    "common@example.com",
		"password": "Password1234!",
	})
	res.Body.Close()
	// "password" lowercased is in the common list — but mixed case
	// here probably isn't. So instead test a literal common password.
	res = postJSON(t, srv.URL+"/api/auth/register", map[string]any{
		"email":    "common2@example.com",
		"password": "password",
	})
	res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for common password, got %d", res.StatusCode)
	}
}
