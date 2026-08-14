package oauth2server_test

// signLogoutToken (plugins/oauth2server/backchannel_logout.go) mints the one
// JWT in the whole library that carries no "exp": iss/aud/sub/iat/jti/events
// and nothing else. That token is POSTed to every relying party the user ever
// authorized that registered a backchannel_logout_uri — including one that
// registered itself through anonymous Dynamic Client Registration — so a
// deployment hands out an eternally-valid, signed assertion naming one of its
// users to parties it has no relationship with. Nothing about a logout token
// needs to live longer than the seconds it takes to deliver it.
//
// It also blocks the fix on the other side of the same trust chain: yauth's
// own asymjwt Signer.Verify has to start requiring exp (a signed JWT is a
// bearer credential with no revocation path), and this is the one token yauth
// mints that such a check would reject.
//
// The path exercised here is the real one: admin suspends a user →
// events.EventUserSuspended → oauth2server's bcl handler fans out to the RP's
// backchannel_logout_uri. We assert on the token the RP actually received, and
// the positive control is that same token still parsing and validating with
// expiration required and its spec-mandated claims intact — a "fix" that stops
// delivering logout tokens at all does not pass.

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

	yauth "github.com/yackey-labs/yauth"
	"github.com/yackey-labs/yauth/auth"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/plugins/admin"
	"github.com/yackey-labs/yauth/plugins/oauth2server"
	"github.com/yackey-labs/yauth/repo/memrepo"
)

func TestBackchannelLogout_TokenCarriesExp(t *testing.T) {
	r := memrepo.New()
	secret := []byte("test-only-jwt-secret-please-change-32b")

	ya, err := yauth.New(r, yauth.NewDefaultConfig()).
		WithJWTSecret(secret).
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

	adminUser, err := r.CreateUser(ctx, domain.NewUser{ID: uuid.NewString(), Email: "admin@idp.test", Role: "admin", CreatedAt: now, UpdatedAt: now})
	if err != nil {
		t.Fatalf("create admin: %v", err)
	}
	target, err := r.CreateUser(ctx, domain.NewUser{ID: uuid.NewString(), Email: "dana@idp.test", Role: "user", CreatedAt: now, UpdatedAt: now})
	if err != nil {
		t.Fatalf("create target: %v", err)
	}

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
	if err := r.CreateConsent(ctx, domain.NewConsent{
		ID: uuid.NewString(), UserID: target.ID, ClientID: clientID,
		Scopes: json.RawMessage(`["openid"]`), CreatedAt: now,
	}); err != nil {
		t.Fatalf("create consent: %v", err)
	}

	adminRaw, _, err := auth.IssueSession(ctx, r, adminUser.ID, nil, nil, time.Hour)
	if err != nil {
		t.Fatalf("issue admin session: %v", err)
	}

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
	expRaw, ok := claims["exp"]
	if !ok {
		t.Fatalf("logout_token has no exp — it stays valid forever at every RP it was delivered to: %v", claims)
	}
	expF, ok := expRaw.(float64)
	if !ok {
		t.Fatalf("exp is not numeric: %#v", expRaw)
	}
	exp := time.Unix(int64(expF), 0)
	if !exp.After(time.Now()) {
		t.Fatalf("logout_token exp is not in the future: %s", exp)
	}
	if d := time.Until(exp); d > time.Hour {
		t.Fatalf("logout_token lifetime %s is far longer than a delivery needs", d)
	}

	// POSITIVE CONTROL: the delivered token is still a usable, spec-shaped
	// logout_token — it validates with expiration required, and carries the
	// audience, subject, issuer and backchannel event an RP keys off (and no
	// nonce, per OIDC BCL §2.4).
	strict := jwt.MapClaims{}
	tok, err := jwt.NewParser(
		jwt.WithValidMethods([]string{"HS256"}),
		jwt.WithExpirationRequired(),
		jwt.WithAudience(clientID),
		jwt.WithIssuer("http://idp.test"),
	).ParseWithClaims(raw, &strict, func(*jwt.Token) (any, error) { return secret, nil })
	if err != nil {
		t.Fatalf("delivered logout_token failed strict validation: %v", err)
	}
	if !tok.Valid {
		t.Fatal("delivered logout_token is not valid")
	}
	if strict["sub"] != target.ID {
		t.Fatalf("logout_token sub mismatch: %v want %v", strict["sub"], target.ID)
	}
	if _, has := strict["nonce"]; has {
		t.Fatal("logout_token must not contain nonce")
	}
	evs, ok := strict["events"].(map[string]any)
	if !ok {
		t.Fatalf("events claim missing: %v", strict["events"])
	}
	if _, ok := evs["http://schemas.openid.net/event/backchannel-logout"]; !ok {
		t.Fatalf("events missing backchannel-logout key: %v", evs)
	}
}
