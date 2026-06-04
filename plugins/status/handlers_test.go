package status_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	yauth "github.com/yackey-labs/yauth"
	"github.com/yackey-labs/yauth/auth"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/plugins/status"
	"github.com/yackey-labs/yauth/repo/gormrepo"
)

// newTestServer builds a YAuth instance with the status plugin registered
// alongside two named placeholder plugins so PluginNames() returns a
// stable, predictable list.
func newTestServer(t *testing.T) (*httptest.Server, *gormrepo.Repo, func()) {
	t.Helper()

	dsn := "file:" + uuid.NewString() + "?mode=memory&cache=shared&_pragma=foreign_keys(1)"
	db, err := gormrepo.OpenSQLite(dsn)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := gormrepo.Migrate(context.Background(), db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	r := gormrepo.New(db)

	ya, err := yauth.New(r, yauth.NewDefaultConfig()).
		WithPlugin(status.New()).
		Build()
	if err != nil {
		t.Fatalf("build yauth: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))
	srv := httptest.NewServer(mux)
	return srv, r, func() { srv.Close() }
}

// seedSession creates a user with the supplied role, issues a session for
// them, and returns the raw cookie value.
func seedSession(t *testing.T, r *gormrepo.Repo, role string) string {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	u, err := r.CreateUser(ctx, domain.NewUser{
		ID:        uuid.NewString(),
		Email:     role + "@example.com",
		Role:      role,
		CreatedAt: now,
		UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	raw, _, err := auth.IssueSession(ctx, r, u.ID, nil, nil, time.Hour)
	if err != nil {
		t.Fatalf("issue session: %v", err)
	}
	return raw
}

func TestStatus_AdminOK(t *testing.T) {
	srv, r, stop := newTestServer(t)
	defer stop()

	tok := seedSession(t, r, "admin")
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/auth/status", nil)
	req.AddCookie(&http.Cookie{Name: "yauth_session", Value: tok})

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}

	var body struct {
		Plugins []string `json:"plugins"`
		Version string   `json:"version"`
	}
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Plugins) != 1 || body.Plugins[0] != "status" {
		t.Fatalf("expected plugins=[status], got %v", body.Plugins)
	}
	if body.Version != status.Version {
		t.Fatalf("expected version %q, got %q", status.Version, body.Version)
	}
}

func TestStatus_NonAdmin403(t *testing.T) {
	srv, r, stop := newTestServer(t)
	defer stop()

	tok := seedSession(t, r, "user")
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/auth/status", nil)
	req.AddCookie(&http.Cookie{Name: "yauth_session", Value: tok})

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", res.StatusCode)
	}
}

func TestStatus_NoAuth401(t *testing.T) {
	srv, _, stop := newTestServer(t)
	defer stop()

	res, err := http.Get(srv.URL + "/api/auth/status")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", res.StatusCode)
	}
}
