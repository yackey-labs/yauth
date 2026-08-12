package emailpassword_test

// POST /register answered a fresh address with 201 + {"user":{...}} + a
// Set-Cookie and an address that already had an account with 200 +
// {"status":"pending_verification"}. Status, body shape and the presence of a
// session cookie ALL disagreed, despite the pending branch existing solely to
// be indistinguishable. Any anonymous caller could ask "does alice work here?"

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	yauth "github.com/yackey-labs/yauth"
	"github.com/yackey-labs/yauth/plugins/emailpassword"
	"github.com/yackey-labs/yauth/repo"
	"github.com/yackey-labs/yauth/repo/memrepo"
)

func newRegisterServer(t *testing.T, reveal bool) (*httptest.Server, repo.Repository) {
	t.Helper()
	r := memrepo.New()
	cfg := yauth.NewDefaultConfig()
	cfg.SessionTTL = time.Hour
	ya, err := yauth.New(r, cfg).
		WithPlugin(emailpassword.New(emailpassword.Config{
			MinPasswordLength:         8,
			HIBPCheck:                 false,
			HIBPCheckSet:              true,
			RevealRegistrationOutcome: reveal,
		})).
		Build()
	if err != nil {
		t.Fatalf("build yauth: %v", err)
	}
	mux := http.NewServeMux()
	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, r
}

// observation is everything an anonymous caller can see about one /register
// response. Anything that differs between a taken and a free address IS the
// oracle.
type observation struct {
	status     int
	body       string
	hasSession bool
}

func observeRegister(t *testing.T, srv *httptest.Server, email, password string) observation {
	t.Helper()
	res := postJSON(t, srv.URL+"/api/auth/register", map[string]any{
		"email": email, "password": password,
	})
	body := drain(res)
	obs := observation{status: res.StatusCode, body: body}
	for _, c := range res.Cookies() {
		if c.Name == "yauth_session" && c.Value != "" {
			obs.hasSession = true
		}
	}
	return obs
}

// TestRegister_DoesNotRevealWhetherTheAddressIsTaken is the regression.
func TestRegister_DoesNotRevealWhetherTheAddressIsTaken(t *testing.T) {
	srv, _ := newRegisterServer(t, false)
	const password = "correct-horse-battery"

	// Seed one account so its address is TAKEN.
	if obs := observeRegister(t, srv, "taken@example.com", password); obs.status >= 400 {
		t.Fatalf("seeding registration failed: %d %s", obs.status, obs.body)
	}

	taken := observeRegister(t, srv, "taken@example.com", password)
	free := observeRegister(t, srv, "free@example.com", password)

	if taken.status != free.status {
		t.Errorf("account-existence oracle via status: taken=%d free=%d", taken.status, free.status)
	}
	if taken.body != free.body {
		t.Errorf("account-existence oracle via body:\n  taken=%s\n   free=%s", taken.body, free.body)
	}
	if taken.hasSession != free.hasSession {
		t.Errorf("account-existence oracle via Set-Cookie: taken=%v free=%v", taken.hasSession, free.hasSession)
	}
	if free.hasSession {
		t.Errorf("neutral mode still issued a session cookie on registration")
	}
}

// TestRegister_StillCreatesTheAccount: neutrality is worthless if it was bought
// by not registering anyone. The account must exist and be able to sign in.
func TestRegister_StillCreatesTheAccount(t *testing.T) {
	srv, r := newRegisterServer(t, false)
	const email, password = "newcomer@example.com", "correct-horse-battery"

	if obs := observeRegister(t, srv, email, password); obs.status != http.StatusOK {
		t.Fatalf("register: %d %s", obs.status, obs.body)
	}
	u, err := r.GetUserByEmail(context.Background(), email)
	if err != nil || u == nil {
		t.Fatalf("register did not create the account: %v", err)
	}

	res := postJSON(t, srv.URL+"/api/auth/login", map[string]any{"email": email, "password": password})
	body := drain(res)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("the registered account cannot sign in: %d %s", res.StatusCode, body)
	}
	var out struct {
		User *struct {
			Email string `json:"email"`
		} `json:"user"`
	}
	_ = json.Unmarshal([]byte(body), &out)
	if out.User == nil || out.User.Email != email {
		t.Fatalf("login did not return the registered user: %s", body)
	}
}

// TestRegister_RevealOptOutRestoresTheLegacyContract: consumers who prefer the
// immediate session over the privacy property must still be able to have it,
// unchanged.
func TestRegister_RevealOptOutRestoresTheLegacyContract(t *testing.T) {
	srv, _ := newRegisterServer(t, true)
	const password = "correct-horse-battery"

	fresh := observeRegister(t, srv, "fresh@example.com", password)
	if fresh.status != http.StatusCreated {
		t.Fatalf("reveal mode: expected 201, got %d (%s)", fresh.status, fresh.body)
	}
	if !fresh.hasSession {
		t.Fatalf("reveal mode: expected a session cookie")
	}
	var out struct {
		User *struct {
			Email string `json:"email"`
		} `json:"user"`
	}
	_ = json.Unmarshal([]byte(fresh.body), &out)
	if out.User == nil || out.User.Email != "fresh@example.com" {
		t.Fatalf("reveal mode: expected the created user in the body, got %s", fresh.body)
	}

	dup := observeRegister(t, srv, "fresh@example.com", password)
	if dup.status != http.StatusOK {
		t.Fatalf("reveal mode: expected the legacy 200 for a duplicate, got %d", dup.status)
	}
}
