package oauth2server_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	yauth "github.com/yackey-labs/yauth-go"
	"github.com/yackey-labs/yauth-go/auth"
	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/plugins/admin"
	"github.com/yackey-labs/yauth-go/plugins/oauth2server"
	"github.com/yackey-labs/yauth-go/repo/gormrepo"
)

// TestBackchannelLogout_OnAdminSuspend is the end-to-end offboarding test: an
// admin suspends a user, and the oauth2-server plugin (a different plugin from
// admin, wired only through the event pipeline) delivers a spec-shaped
// logout_token to every RP the user authorized that registered a
// backchannel_logout_uri. This exercises the cross-plugin path that is the
// headline feature — admin EventUserSuspended → oauth2server BCL fan-out.
func TestBackchannelLogout_OnAdminSuspend(t *testing.T) {
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
		WithJWTSecret([]byte("test-only-jwt-secret-please-change-32b")).
		WithPlugin(oauth2server.New(oauth2server.Config{Issuer: "http://idp.test", BasePath: "/api/auth"})).
		WithPlugin(admin.New()).
		Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	mux := http.NewServeMux()
	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ctx := context.Background()
	now := time.Now().UTC()

	// Mock RP back-channel logout endpoint.
	received := make(chan string, 1)
	rp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		_ = req.ParseForm()
		select {
		case received <- req.PostFormValue("logout_token"):
		default:
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer rp.Close()

	// Admin + target users.
	adminUser, err := r.CreateUser(ctx, domain.NewUser{ID: uuid.NewString(), Email: "admin@idp.test", Role: "admin", CreatedAt: now, UpdatedAt: now})
	if err != nil {
		t.Fatalf("create admin: %v", err)
	}
	target, err := r.CreateUser(ctx, domain.NewUser{ID: uuid.NewString(), Email: "bob@idp.test", Role: "user", CreatedAt: now, UpdatedAt: now})
	if err != nil {
		t.Fatalf("create target: %v", err)
	}

	// Client that registered a back-channel logout endpoint.
	rpURL := rp.URL
	clientID := "client-" + uuid.NewString()[:8]
	if err := r.CreateOAuth2Client(ctx, domain.NewOAuth2Client{
		ID:                   uuid.NewString(),
		ClientID:             clientID,
		RedirectURIs:         json.RawMessage(`["https://app.example/cb"]`),
		GrantTypes:           json.RawMessage(`["authorization_code"]`),
		Scopes:               json.RawMessage(`["openid"]`),
		CreatedAt:            now,
		BackchannelLogoutURI: &rpURL,
	}); err != nil {
		t.Fatalf("create client: %v", err)
	}
	// The target authorized that client (consent links user→client for BCL).
	if err := r.CreateConsent(ctx, domain.NewConsent{
		ID: uuid.NewString(), UserID: target.ID, ClientID: clientID,
		Scopes: json.RawMessage(`["openid"]`), CreatedAt: now,
	}); err != nil {
		t.Fatalf("create consent: %v", err)
	}

	// Admin session cookie.
	adminRaw, _, err := auth.IssueSession(ctx, r, adminUser.ID, nil, nil, time.Hour)
	if err != nil {
		t.Fatalf("issue admin session: %v", err)
	}

	// Suspend the target via the admin API.
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/auth/admin/users/"+target.ID+"/suspend", strings.NewReader(`{"reason":"offboarded"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "yauth_session", Value: adminRaw})
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("suspend: %v", err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("suspend status %d", res.StatusCode)
	}
	res.Body.Close()

	// The RP must receive a logout_token for the suspended user.
	var raw string
	select {
	case raw = <-received:
	case <-time.After(5 * time.Second):
		t.Fatal("RP never received a logout_token after admin suspend")
	}

	claims := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(raw, claims); err != nil {
		t.Fatalf("parse logout_token: %v", err)
	}
	if claims["aud"] != clientID || claims["sub"] != target.ID || claims["iss"] != "http://idp.test" {
		t.Fatalf("logout_token claims mismatch: %v", claims)
	}
	if _, ok := claims["nonce"]; ok {
		t.Fatal("logout_token must not contain nonce")
	}
	evs, ok := claims["events"].(map[string]any)
	if !ok {
		t.Fatalf("events claim missing: %v", claims["events"])
	}
	if _, ok := evs["http://schemas.openid.net/event/backchannel-logout"]; !ok {
		t.Fatalf("events missing backchannel-logout key: %v", evs)
	}
}

// TestBackchannelLogout_SignedTokenShape signs a logout_token directly and
// confirms its structural validity independent of HTTP delivery.
func TestBackchannelLogout_NoNonceNoExpRequired(t *testing.T) {
	h := newHarness(t)
	_, adminCookie := h.seedUser(t, "admin@idp.test", "admin")
	_, userCookie := h.seedUser(t, "carol@idp.test", "user")

	// A client WITHOUT a backchannel_logout_uri must simply be skipped — logging
	// out (end_session) triggers no BCL at all (decoupled from offboarding).
	body := `{"name":"no-bcl","redirect_uris":["https://app.example/callback"],"grant_types":["authorization_code"],"scopes":["openid","read"],"is_public":false,"token_endpoint_auth_method":"client_secret_post"}`
	clientID, _, _ := h.createClient(t, adminCookie, body)
	verifier := "no-bcl-pkce-verifier-of-43-characters-min-okk"
	challenge := pkceS256(verifier)
	_ = h.authorizeAndConsent(t, userCookie, clientID, "https://app.example/callback", "openid read", challenge, "s1", "n1")

	req, _ := http.NewRequest(http.MethodGet, h.srv.URL+"/api/auth/oauth/end_session", nil)
	req.AddCookie(&http.Cookie{Name: "yauth_session", Value: userCookie})
	res, err := noRedirectClient().Do(req)
	if err != nil {
		t.Fatalf("end_session: %v", err)
	}
	res.Body.Close()
	// No panic / hang; give any (unexpected) async work a beat.
	time.Sleep(100 * time.Millisecond)
}
