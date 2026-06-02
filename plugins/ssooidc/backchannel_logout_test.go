package ssooidc

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/yackey-labs/yauth-go/auth"
	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/repo/memrepo"
)

// signLogoutTokenForTest mints a BCL logout_token signed by the fake IdP key.
func (i *fakeIDP) signLogoutTokenForTest(t *testing.T, aud, sub, jti string, withEvent, withNonce bool) string {
	t.Helper()
	tok := jwt.New(jwt.SigningMethodRS256)
	tok.Header["kid"] = i.kid
	claims := jwt.MapClaims{
		"iss": i.issuer,
		"aud": aud,
		"sub": sub,
		"iat": time.Now().UTC().Unix(),
		"jti": jti,
	}
	if withEvent {
		claims["events"] = map[string]any{
			"http://schemas.openid.net/event/backchannel-logout": map[string]any{},
		}
	}
	if withNonce {
		claims["nonce"] = "should-not-be-here"
	}
	tok.Claims = claims
	signed, err := tok.SignedString(i.key)
	if err != nil {
		t.Fatalf("sign logout_token: %v", err)
	}
	return signed
}

// bclTestEnv wires a memrepo + ssooidc server with one active OIDC connection
// against a fake IdP, a local user linked to IdP sub "external-sub-1", and an
// active session for that user. Returns the server, repo, IdP, and raw session.
func bclTestEnv(t *testing.T) (*httptest.Server, *memrepo.Repo, *fakeIDP, *domain.User, string) {
	t.Helper()
	p := newPlugin(t)
	r := memrepo.New()
	ctx := context.Background()
	now := time.Now().UTC()
	idp := newFakeIDP(t, "rp-1")

	user, err := r.CreateUser(ctx, domain.NewUser{ID: uuid.NewString(), Email: "u@example.com", Role: "user", CreatedAt: now, UpdatedAt: now})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	discoveryURL := idp.issuer + "/.well-known/openid-configuration"
	provider := "oidc:" + IssuerKeyFromDiscoveryURL(discoveryURL)
	if _, err := r.CreateExternalIdentity(ctx, domain.NewExternalIdentity{
		ID: uuid.NewString(), UserID: user.ID, Provider: provider,
		ExternalID: "external-sub-1", LinkedAt: now, LastLoginAt: now,
	}); err != nil {
		t.Fatalf("create external identity: %v", err)
	}
	rawSession, _, err := auth.IssueSession(ctx, r, user.ID, nil, nil, time.Hour)
	if err != nil {
		t.Fatalf("issue session: %v", err)
	}

	cfgBytes, err := marshalOidcConfig(p.cfg.EncryptionKey, OidcConnectionConfig{
		DiscoveryURL: discoveryURL, ClientID: "rp-1", ClientSecret: "rp-secret",
	})
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	org, _ := r.CreateOrganization(ctx, domain.NewOrganization{ID: uuid.NewString(), Name: "Acme", Slug: "acme", CreatedAt: now, UpdatedAt: now})
	if _, err := r.CreateSsoConnection(ctx, domain.NewSsoConnection{
		ID: uuid.NewString(), OrganizationID: org.ID, Kind: domain.ConnectionKindOIDCClient,
		Name: "Okta", Status: domain.ConnectionStatusActive, Config: cfgBytes,
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("create connection: %v", err)
	}

	mux := http.NewServeMux()
	host := newFakeHost(r, "")
	p.Routes(host, mux, "")
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	host.base = srv.URL
	return srv, r, idp, &user, rawSession
}

func postLogoutToken(t *testing.T, srv *httptest.Server, token string) *http.Response {
	t.Helper()
	form := url.Values{}
	form.Set("logout_token", token)
	resp, err := http.PostForm(srv.URL+"/sso/backchannel-logout", form)
	if err != nil {
		t.Fatalf("post logout_token: %v", err)
	}
	return resp
}

// TestBackchannelLogout_RevokesLocalSession is the end-to-end RP consumer test:
// a valid logout_token from the upstream IdP terminates the local session of
// the mapped user — completing OIDC instant termination across the federation.
func TestBackchannelLogout_RevokesLocalSession(t *testing.T) {
	srv, r, idp, user, rawSession := bclTestEnv(t)
	ctx := context.Background()

	// Precondition: session is valid.
	if _, err := r.GetSessionByTokenHash(ctx, auth.HashToken(rawSession)); err != nil {
		t.Fatalf("precondition: session should exist: %v", err)
	}

	token := idp.signLogoutTokenForTest(t, "rp-1", "external-sub-1", uuid.NewString(), true, false)
	resp := postLogoutToken(t, srv, token)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	// The user's session must be revoked.
	if _, err := r.GetSessionByTokenHash(ctx, auth.HashToken(rawSession)); err == nil {
		t.Fatal("expected local session revoked after back-channel logout")
	}
	_ = user
}

// TestBackchannelLogout_RejectsNonce proves a logout_token carrying a nonce is
// rejected (OIDC BCL §2.4 forbids it).
func TestBackchannelLogout_RejectsNonce(t *testing.T) {
	srv, r, idp, _, rawSession := bclTestEnv(t)
	ctx := context.Background()

	token := idp.signLogoutTokenForTest(t, "rp-1", "external-sub-1", uuid.NewString(), true, true)
	resp := postLogoutToken(t, srv, token)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for nonce-bearing token, got %d", resp.StatusCode)
	}
	// Session must survive a rejected token.
	if _, err := r.GetSessionByTokenHash(ctx, auth.HashToken(rawSession)); err != nil {
		t.Fatal("session should NOT be revoked by a rejected logout_token")
	}
}

// TestBackchannelLogout_RejectsMissingEvent proves a token without the
// backchannel-logout event claim is rejected.
func TestBackchannelLogout_RejectsMissingEvent(t *testing.T) {
	srv, _, idp, _, _ := bclTestEnv(t)
	token := idp.signLogoutTokenForTest(t, "rp-1", "external-sub-1", uuid.NewString(), false, false)
	resp := postLogoutToken(t, srv, token)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for token without events claim, got %d", resp.StatusCode)
	}
}

// TestBackchannelLogout_ReplayIsIdempotent proves a re-sent jti is accepted as a
// no-op (200) rather than re-processed.
func TestBackchannelLogout_ReplayIsIdempotent(t *testing.T) {
	srv, _, idp, _, _ := bclTestEnv(t)
	jti := uuid.NewString()
	token := idp.signLogoutTokenForTest(t, "rp-1", "external-sub-1", jti, true, false)

	first := postLogoutToken(t, srv, token)
	first.Body.Close()
	if first.StatusCode != http.StatusOK {
		t.Fatalf("first delivery: expected 200, got %d", first.StatusCode)
	}
	second := postLogoutToken(t, srv, token)
	second.Body.Close()
	if second.StatusCode != http.StatusOK {
		t.Fatalf("replay: expected idempotent 200, got %d", second.StatusCode)
	}
}
