package yauth_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"

	yauth "github.com/yackey-labs/yauth-go"
	"github.com/yackey-labs/yauth-go/plugins/emailpassword"
	"github.com/yackey-labs/yauth-go/repo/gormrepo"
)

func newTestServer(t *testing.T) (*httptest.Server, func()) {
	t.Helper()

	db, err := gormrepo.OpenSQLite("file::memory:?cache=shared&_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := gormrepo.Migrate(context.Background(), db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	repo := gormrepo.New(db)

	ya, err := yauth.New(repo, yauth.NewDefaultConfig()).
		WithPlugin(emailpassword.New(emailpassword.Config{})).
		Build()
	if err != nil {
		t.Fatalf("build yauth: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))
	srv := httptest.NewServer(mux)
	return srv, func() { srv.Close() }
}

// jsonClient wraps an *http.Client with helpers that match the email-
// password plugin's request/response shapes.
type jsonClient struct{ c *http.Client }

func newJSONClient(t *testing.T) *jsonClient {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar: %v", err)
	}
	return &jsonClient{c: &http.Client{Jar: jar}}
}

func (j *jsonClient) post(t *testing.T, url string, body any) *http.Response {
	t.Helper()
	buf, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(buf))
	if err != nil {
		t.Fatalf("new req: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := j.c.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	return res
}

func (j *jsonClient) get(t *testing.T, url string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("new req: %v", err)
	}
	res, err := j.c.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	return res
}

func drain(res *http.Response) string {
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return string(b)
}

func TestEmailPasswordEndToEnd(t *testing.T) {
	srv, stop := newTestServer(t)
	defer stop()

	cl := newJSONClient(t)
	const email = "alice@example.com"
	const oldPW = "correct horse battery staple"
	const newPW = "another long sufficient password 123"

	// 1. register
	res := cl.post(t, srv.URL+"/api/auth/register", map[string]string{
		"email":    email,
		"password": oldPW,
	})
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("register: expected 201, got %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()

	// 2. /session via cookie set by register
	res = cl.get(t, srv.URL+"/api/auth/session")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("session after register: expected 200, got %d (%s)", res.StatusCode, drain(res))
	}
	var sessBody struct {
		User struct {
			Email string `json:"email"`
		} `json:"user"`
	}
	if err := json.NewDecoder(res.Body).Decode(&sessBody); err != nil {
		t.Fatalf("decode session: %v", err)
	}
	res.Body.Close()
	if sessBody.User.Email != email {
		t.Fatalf("session: expected %q, got %q", email, sessBody.User.Email)
	}

	// 3. logout
	res = cl.post(t, srv.URL+"/api/auth/logout", struct{}{})
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("logout: expected 204, got %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()

	// 4. /session after logout → 401
	res = cl.get(t, srv.URL+"/api/auth/session")
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("session after logout: expected 401, got %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()

	// 5. login again
	res = cl.post(t, srv.URL+"/api/auth/login", map[string]string{
		"email":    email,
		"password": oldPW,
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("login: expected 200, got %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()

	// 6. change password
	res = cl.post(t, srv.URL+"/api/auth/change-password", map[string]string{
		"old_password": oldPW,
		"new_password": newPW,
	})
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("change-password: expected 204, got %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()

	// 7. /session still works (we re-issued)
	res = cl.get(t, srv.URL+"/api/auth/session")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("session after change-password: expected 200, got %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()

	// 8. logout, then re-login with new password
	res = cl.post(t, srv.URL+"/api/auth/logout", struct{}{})
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("logout #2: expected 204, got %d", res.StatusCode)
	}
	res.Body.Close()

	res = cl.post(t, srv.URL+"/api/auth/login", map[string]string{
		"email":    email,
		"password": oldPW,
	})
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("login w/ old pw: expected 401, got %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()

	res = cl.post(t, srv.URL+"/api/auth/login", map[string]string{
		"email":    email,
		"password": newPW,
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("login w/ new pw: expected 200, got %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()
}

func TestRegister_RejectsShortPassword(t *testing.T) {
	srv, stop := newTestServer(t)
	defer stop()

	cl := newJSONClient(t)
	res := cl.post(t, srv.URL+"/api/auth/register", map[string]string{
		"email":    "bob@example.com",
		"password": "short",
	})
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()
}

func TestRegister_RejectsDuplicateEmail(t *testing.T) {
	srv, stop := newTestServer(t)
	defer stop()

	cl := newJSONClient(t)
	body := map[string]string{
		"email":    "carol@example.com",
		"password": "correct horse battery staple",
	}
	res := cl.post(t, srv.URL+"/api/auth/register", body)
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("first register: %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()

	res = cl.post(t, srv.URL+"/api/auth/register", body)
	if res.StatusCode != http.StatusConflict {
		t.Fatalf("dup register: expected 409, got %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()
}
