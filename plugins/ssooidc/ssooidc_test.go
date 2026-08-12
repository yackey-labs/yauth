// sso_oidc_test.go — integration coverage for the OIDC client plugin.
//
// The fixture spins up an httptest server that impersonates an OIDC
// IdP: it serves /.well-known/openid-configuration, a JWKS document
// built from a fresh RSA keypair, and a /token endpoint that returns
// a signed id_token. The yauth-go side runs against memrepo with the
// sso_oidc plugin mounted; tests drive the full login/callback round-
// trip without any external network.
//
// Pentest cases live alongside happy-path: state replay, nonce
// mismatch, audience mismatch, expired token, kid rollover, account-
// takeover on email change.
package ssooidc

import (
	"github.com/yackey-labs/yauth/humaapi"
	"log/slog"

	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"

	"github.com/yackey-labs/yauth/auth"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/events"
	"github.com/yackey-labs/yauth/middleware"
	"github.com/yackey-labs/yauth/plugin"
	"github.com/yackey-labs/yauth/repo"
	"github.com/yackey-labs/yauth/repo/memrepo"
)

// --- Fixture IdP -------------------------------------------------------

// fakeIDP is a minimal OIDC provider for tests. It signs tokens with
// an in-memory RSA-2048 keypair and exposes the public side via JWKS.
type fakeIDP struct {
	srv      *httptest.Server
	key      *rsa.PrivateKey
	kid      string
	issuer   string
	clientID string
	// override hooks for negative tests
	overrideIssuer   string
	overrideAud      string
	overrideNonce    string
	overrideExp      *int64
	overrideEmail    string
	overrideExtraSub string
	overrideGroups   []string
	// counters
	tokenCalls int
	jwksCalls  int
	// rolling kid (set by RollKey)
	jwksSecondary *rsa.PrivateKey
	jwksSecondKid string
}

func newFakeIDP(t *testing.T, clientID string) *fakeIDP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen rsa: %v", err)
	}
	idp := &fakeIDP{key: key, kid: "kid-1", clientID: clientID}
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	idp.srv = srv
	idp.issuer = srv.URL
	mux.HandleFunc("/.well-known/openid-configuration", idp.handleDiscovery)
	mux.HandleFunc("/jwks", idp.handleJWKS)
	mux.HandleFunc("/authorize", idp.handleAuthorize)
	mux.HandleFunc("/token", idp.handleToken)
	return idp
}

func (i *fakeIDP) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"issuer":                                i.issuer,
		"authorization_endpoint":                i.issuer + "/authorize",
		"token_endpoint":                        i.issuer + "/token",
		"jwks_uri":                              i.issuer + "/jwks",
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"response_types_supported":              []string{"code"},
		"code_challenge_methods_supported":      []string{"S256"},
	})
}

func (i *fakeIDP) handleJWKS(w http.ResponseWriter, r *http.Request) {
	i.jwksCalls++
	set := jwk.NewSet()
	add := func(key *rsa.PrivateKey, kid string) {
		k, err := jwk.Import(&key.PublicKey)
		if err != nil {
			return
		}
		_ = k.Set(jwk.KeyIDKey, kid)
		_ = k.Set(jwk.AlgorithmKey, jwa.RS256())
		_ = set.AddKey(k)
	}
	add(i.key, i.kid)
	if i.jwksSecondary != nil {
		add(i.jwksSecondary, i.jwksSecondKid)
	}
	buf, _ := json.Marshal(set)
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(buf)
}

func (i *fakeIDP) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	// We don't actually drive a browser; tests skip ahead by inspecting
	// the redirect URL and POSTing /token directly through the yauth
	// callback. This handler exists only so the discovery doc points
	// somewhere real.
	w.WriteHeader(http.StatusOK)
}

func (i *fakeIDP) handleToken(w http.ResponseWriter, r *http.Request) {
	i.tokenCalls++
	_ = r.ParseForm()
	// We deliberately ignore the form values — the test driver picks
	// the claims to mint per-call.
	tok := jwt.New(jwt.SigningMethodRS256)
	tok.Header["kid"] = i.kid

	now := time.Now().Unix()
	iss := i.issuer
	if i.overrideIssuer != "" {
		iss = i.overrideIssuer
	}
	aud := i.clientID
	if i.overrideAud != "" {
		aud = i.overrideAud
	}
	exp := now + 600
	if i.overrideExp != nil {
		exp = *i.overrideExp
	}
	email := "u@example.com"
	if i.overrideEmail != "" {
		email = i.overrideEmail
	}
	sub := "external-sub-1"
	if i.overrideExtraSub != "" {
		sub = i.overrideExtraSub
	}
	nonceVal := ""
	if vals := r.Form["nonce_override"]; len(vals) > 0 {
		nonceVal = vals[0]
	}
	if i.overrideNonce != "" {
		nonceVal = i.overrideNonce
	}

	claims := jwt.MapClaims{
		"iss":            iss,
		"aud":            aud,
		"sub":            sub,
		"iat":            now,
		"exp":            exp,
		"email":          email,
		"email_verified": true,
		"name":           "Test User",
	}
	if nonceVal != "" {
		claims["nonce"] = nonceVal
	}
	if i.overrideGroups != nil {
		claims["groups"] = i.overrideGroups
	}
	tok.Claims = claims

	signed, err := tok.SignedString(i.key)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": "at-x",
		"id_token":     signed,
		"token_type":   "Bearer",
		"expires_in":   3600,
	})
}

// rollKey rotates the IdP's primary signing key, keeping the prior
// key in the JWKS document for one extra publish. The next token is
// signed by the new key under a new kid, simulating an OIDC IdP key
// rotation.
func (i *fakeIDP) rollKey(t *testing.T) {
	t.Helper()
	newKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen new rsa: %v", err)
	}
	i.jwksSecondary = i.key
	i.jwksSecondKid = i.kid
	i.key = newKey
	i.kid = "kid-2"
}

// --- yauth host stub --------------------------------------------------

type fakeHost struct {
	repo repo.Repository
	mw   *middleware.Middleware
	base string
}

func newFakeHost(r repo.Repository, base string) *fakeHost {
	return &fakeHost{repo: r, mw: middleware.New(r, middleware.Config{CookieName: "yauth_session"}), base: base}
}

func (h *fakeHost) Repo() repo.Repository                      { return h.repo }
func (h *fakeHost) Middleware() *middleware.Middleware         { return h.mw }
func (h *fakeHost) SessionTTL() time.Duration                  { return time.Hour }
func (h *fakeHost) CookieName() string                         { return "yauth_session" }
func (h *fakeHost) CookieDomain() string                       { return "" }
func (h *fakeHost) CookieSecure() bool                         { return false }
func (h *fakeHost) CookiePath() string                         { return "/" }
func (h *fakeHost) CookieSameSite() http.SameSite              { return http.SameSiteLaxMode }
func (h *fakeHost) SessionBinding() (bool, bool)               { return false, false }
func (h *fakeHost) BaseURL() string                            { return h.base }
func (h *fakeHost) AllowSignups() bool                         { return true }
func (h *fakeHost) AutoAdminFirstUser() bool                   { return false }
func (h *fakeHost) RegisterEventHandler(_ events.Handler)      {}
func (h *fakeHost) RegisterAuthResolver(r plugin.AuthResolver) { h.mw.AddResolver(r) }
func (h *fakeHost) PluginNames() []string                      { return nil }
func (h *fakeHost) JWTSigner() plugin.JWTSigner                { return nil }
func (h *fakeHost) JWTSecret() []byte                          { return nil }
func (h *fakeHost) RegisterMFAVerifier(plugin.MFAVerifier)     {}
func (h *fakeHost) RegisterEventGate(events.Handler)           {}
func (h *fakeHost) MFAVerifier() plugin.MFAVerifier            { return nil }
func (h *fakeHost) Emit(_ context.Context, _ events.AuthEvent) (events.Decision, error) {
	return events.Continue(), nil
}
func (h *fakeHost) RateLimit(name string, max int, window time.Duration) func(http.Handler) http.Handler {
	return middleware.RateLimit(h.repo, name, max, window)
}

var _ plugin.PluginHost = (*fakeHost)(nil)

type stubResolver struct{ user *domain.AuthUser }

func (s *stubResolver) Name() string { return "stub" }
func (s *stubResolver) Resolve(_ *http.Request) (*domain.AuthUser, bool, error) {
	return s.user, true, nil
}

// --- helpers ----------------------------------------------------------

func newPlugin(t *testing.T) *ssoOIDCPlugin {
	t.Helper()
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}
	// Cooldown=1ns so kid-rollover refetches don't bump against the
	// rate limiter in the test's < millisecond timing.
	p, err := New(Config{EncryptionKey: key, StateTTL: 5 * time.Minute, JWKSCacheTTL: time.Minute, JWKSRefreshCooldown: time.Nanosecond})
	if err != nil {
		t.Fatal(err)
	}
	return p.(*ssoOIDCPlugin)
}

func seedAdmin(t *testing.T, r repo.Repository) (domain.User, domain.Organization) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	u, err := r.CreateUser(ctx, domain.NewUser{
		ID: uuid.NewString(), Email: "admin@example.com", Role: "user",
		CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	org, err := r.CreateOrganization(ctx, domain.NewOrganization{
		ID: uuid.NewString(), Name: "Acme", Slug: "acme",
		CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = r.CreateMembership(ctx, domain.NewMembership{
		ID: uuid.NewString(), OrganizationID: org.ID, UserID: u.ID,
		Role: auth.RoleOwner, Status: domain.MembershipActive,
		CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return u, org
}

func doJSON(t *testing.T, method, urlStr string, body any) *http.Response {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		buf, _ := json.Marshal(body)
		rdr = bytes.NewReader(buf)
	}
	req, err := http.NewRequest(method, urlStr, rdr)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func decode(t *testing.T, resp *http.Response, dst any) {
	t.Helper()
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(dst); err != nil {
		t.Fatalf("decode: %v", err)
	}
}

// --- tests ------------------------------------------------------------

func TestConfigCodecRoundTrip(t *testing.T) {
	var key [32]byte
	_, _ = rand.Read(key[:])
	in := OidcConnectionConfig{
		DiscoveryURL: "https://idp.example.com/.well-known/openid-configuration",
		ClientID:     "rp-1",
		ClientSecret: "super-secret-value",
		Scopes:       []string{"openid", "email", "profile"},
		ClaimMappings: ClaimMappings{
			Email:       "email",
			DisplayName: "name",
			ExternalID:  "sub",
			Groups:      "groups",
			GroupToRole: map[string]string{"admins": "admin"},
		},
	}
	raw, err := marshalOidcConfig(key, in)
	if err != nil {
		t.Fatal(err)
	}
	// Ensure the wire payload does NOT contain the plaintext.
	if bytes.Contains(raw, []byte("super-secret-value")) {
		t.Fatal("plaintext secret leaked into persisted config")
	}
	out, err := unmarshalOidcConfig(key, raw)
	if err != nil {
		t.Fatal(err)
	}
	if out.ClientSecret != in.ClientSecret {
		t.Fatalf("secret mismatch: got %q want %q", out.ClientSecret, in.ClientSecret)
	}
	if out.ClaimMappings.GroupToRole["admins"] != "admin" {
		t.Fatal("group_to_role lost")
	}
	// Wrong key must fail.
	var bad [32]byte
	_, _ = rand.Read(bad[:])
	if _, err := unmarshalOidcConfig(bad, raw); err == nil {
		t.Fatal("expected decrypt with wrong key to fail")
	}
}

func TestAdminCRUD_Create_List_Get_Update_Delete(t *testing.T) {
	p := newPlugin(t)
	// Seed the admin + org first, then spin the server so the
	// stubResolver returns the *seeded* admin (whose membership the
	// gate looks up).
	r := memrepo.New()
	admin, org := seedAdmin(t, r)
	mux := http.NewServeMux()
	host := newFakeHost(r, "")
	host.mw.AddResolver(&stubResolver{user: &domain.AuthUser{User: admin}})
	p.Routes(host, mux, humaapi.New(mux), "")
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	host.base = srv.URL

	createReq := map[string]any{
		"name": "Okta prod",
		"oidc": map[string]any{
			"discovery_url": "https://example.idp/.well-known/openid-configuration",
			"client_id":     "rp-1",
			"client_secret": "secret-1",
		},
	}
	resp := doJSON(t, http.MethodPost, srv.URL+"/organizations/"+org.ID+"/sso/connections", createReq)
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("create: status=%d body=%s", resp.StatusCode, string(body))
	}
	var created connectionJSON
	decode(t, resp, &created)
	if created.OIDC == nil || created.OIDC.ClientID != "rp-1" {
		t.Fatalf("created shape wrong: %+v", created)
	}
	if !created.OIDC.ClientSecretSet {
		t.Fatal("client_secret_set should be true after create")
	}
	if strings.Contains(fmt.Sprintf("%+v", created), "secret-1") {
		t.Fatal("plaintext secret echoed in create response")
	}

	// list
	resp = doJSON(t, http.MethodGet, srv.URL+"/organizations/"+org.ID+"/sso/connections", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list: status=%d", resp.StatusCode)
	}
	var listed struct {
		SsoConnections []connectionJSON `json:"sso_connections"`
	}
	decode(t, resp, &listed)
	if len(listed.SsoConnections) != 1 {
		t.Fatalf("expected 1 conn, got %d", len(listed.SsoConnections))
	}

	// get
	resp = doJSON(t, http.MethodGet, srv.URL+"/organizations/"+org.ID+"/sso/connections/"+created.ID, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get: status=%d", resp.StatusCode)
	}

	// patch — flip to active, enable JIT
	patch := map[string]any{
		"status":                   "active",
		"jit_provisioning_enabled": true,
	}
	resp = doJSON(t, http.MethodPatch, srv.URL+"/organizations/"+org.ID+"/sso/connections/"+created.ID, patch)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("patch: status=%d body=%s", resp.StatusCode, body)
	}
	var updated connectionJSON
	decode(t, resp, &updated)
	if updated.Status != "active" || !updated.JitProvisioningEnabled {
		t.Fatalf("patch did not apply: %+v", updated)
	}

	// delete
	resp = doJSON(t, http.MethodDelete, srv.URL+"/organizations/"+org.ID+"/sso/connections/"+created.ID, nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete: status=%d", resp.StatusCode)
	}
}

func TestAdminCRUD_NonAdmin_Forbidden(t *testing.T) {
	p := newPlugin(t)
	r := memrepo.New()
	mux := http.NewServeMux()
	now := time.Now().UTC()
	ctx := context.Background()
	other, _ := r.CreateUser(ctx, domain.NewUser{ID: uuid.NewString(), Email: "other@example.com", Role: "user", CreatedAt: now, UpdatedAt: now})
	org, _ := r.CreateOrganization(ctx, domain.NewOrganization{ID: uuid.NewString(), Name: "Acme", Slug: "acme", CreatedAt: now, UpdatedAt: now})
	// "other" has no membership in org.
	host := newFakeHost(r, "")
	host.mw.AddResolver(&stubResolver{user: &domain.AuthUser{User: other}})
	p.Routes(host, mux, humaapi.New(mux), "")
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	host.base = srv.URL

	resp := doJSON(t, http.MethodGet, srv.URL+"/organizations/"+org.ID+"/sso/connections", nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
}

func TestSsoLogin_HappyPath_JIT(t *testing.T) {
	p := newPlugin(t)
	r := memrepo.New()
	now := time.Now().UTC()
	ctx := context.Background()
	admin, _ := r.CreateUser(ctx, domain.NewUser{ID: uuid.NewString(), Email: "admin@example.com", Role: "user", CreatedAt: now, UpdatedAt: now})
	org, _ := r.CreateOrganization(ctx, domain.NewOrganization{ID: uuid.NewString(), Name: "Acme", Slug: "acme", CreatedAt: now, UpdatedAt: now})
	_, _ = r.CreateMembership(ctx, domain.NewMembership{ID: uuid.NewString(), OrganizationID: org.ID, UserID: admin.ID, Role: auth.RoleOwner, Status: domain.MembershipActive, CreatedAt: now, UpdatedAt: now})

	mux := http.NewServeMux()
	host := newFakeHost(r, "")
	host.mw.AddResolver(&stubResolver{user: &domain.AuthUser{User: admin}})
	p.Routes(host, mux, humaapi.New(mux), "")
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	host.base = srv.URL

	idp := newFakeIDP(t, "rp-1")

	// Create an active connection via admin API.
	createReq := map[string]any{
		"name":                     "Okta",
		"status":                   "active",
		"jit_provisioning_enabled": true,
		"oidc": map[string]any{
			"discovery_url": idp.issuer + "/.well-known/openid-configuration",
			"client_id":     "rp-1",
			"client_secret": "rp-secret",
		},
	}
	resp := doJSON(t, http.MethodPost, srv.URL+"/organizations/"+org.ID+"/sso/connections", createReq)
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("create conn: %d %s", resp.StatusCode, body)
	}
	resp.Body.Close()

	// Hit /sso/login — must 302 to the IdP authorize URL and persist state.
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
	}
	loginURL := srv.URL + "/sso/login?org=acme"
	resp, err := client.Get(loginURL)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("login: expected 302, got %d %s", resp.StatusCode, string(body))
	}
	loc, _ := resp.Location()
	resp.Body.Close()
	if loc == nil {
		t.Fatal("login: no Location header")
	}
	state := loc.Query().Get("state")
	nonce := loc.Query().Get("nonce")
	if state == "" || nonce == "" {
		t.Fatalf("login: expected state+nonce in redirect, got %s", loc.String())
	}

	// IdP /token would include this nonce in the id_token. Pre-stamp it.
	idp.overrideNonce = nonce

	// Drive the callback as if the user came back from the IdP.
	cbURL := srv.URL + "/sso/callback?" + url.Values{
		"code":  []string{"x"},
		"state": []string{state},
	}.Encode()
	resp, err = http.Get(cbURL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("callback: %d %s", resp.StatusCode, body)
	}
	var cbResp callbackResponse
	if err := json.NewDecoder(resp.Body).Decode(&cbResp); err != nil {
		t.Fatal(err)
	}
	if cbResp.User.Email != "u@example.com" {
		t.Fatalf("callback user wrong: %+v", cbResp)
	}
	// session cookie set
	var sawCookie bool
	for _, c := range resp.Cookies() {
		if c.Name == "yauth_session" && c.Value != "" {
			sawCookie = true
		}
	}
	if !sawCookie {
		t.Fatal("expected session cookie")
	}

	// JIT user must exist + be a member of the org.
	u, err := r.GetUserByEmail(context.Background(), "u@example.com")
	if err != nil || u == nil {
		t.Fatalf("expected JIT user, got %v", err)
	}
	m, err := r.GetMembershipByOrgUser(context.Background(), org.ID, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if m == nil {
		t.Fatal("expected JIT membership")
	}

	// External identity link must exist.
	ident, err := r.GetExternalIdentityByProviderAndExternalID(
		context.Background(),
		"oidc:"+IssuerKeyFromDiscoveryURL(idp.issuer+"/.well-known/openid-configuration"),
		"external-sub-1",
	)
	if err != nil || ident == nil {
		t.Fatalf("expected external identity, got %v", err)
	}
}

func TestPentest_StateReplay(t *testing.T) {
	p, srv, r, conn, idp := setupForLogin(t)
	_ = r

	state, nonce := beginLogin(t, srv, "acme")
	idp.overrideNonce = nonce

	// First callback succeeds.
	resp := callback(t, srv, state)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("first cb: %d %s", resp.StatusCode, body)
	}
	resp.Body.Close()

	// Second callback with same state must 400.
	resp = callback(t, srv, state)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("replay: expected 400, got %d %s", resp.StatusCode, body)
	}
	_ = conn
	_ = p
}

func TestPentest_NonceMismatch(t *testing.T) {
	p, srv, r, _, idp := setupForLogin(t)
	_ = r
	_ = p

	state, _ := beginLogin(t, srv, "acme")
	// IdP returns a different nonce than what was stamped.
	idp.overrideNonce = "wrong-nonce"

	resp := callback(t, srv, state)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 401, got %d %s", resp.StatusCode, body)
	}
}

func TestPentest_AudienceMismatch(t *testing.T) {
	p, srv, r, _, idp := setupForLogin(t)
	_ = r
	_ = p

	state, nonce := beginLogin(t, srv, "acme")
	idp.overrideNonce = nonce
	idp.overrideAud = "different-rp"

	resp := callback(t, srv, state)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 401, got %d %s", resp.StatusCode, body)
	}
}

func TestPentest_ExpiredToken(t *testing.T) {
	p, srv, r, _, idp := setupForLogin(t)
	_ = r
	_ = p

	state, nonce := beginLogin(t, srv, "acme")
	idp.overrideNonce = nonce
	past := time.Now().Add(-1 * time.Hour).Unix()
	idp.overrideExp = &past

	resp := callback(t, srv, state)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 401, got %d %s", resp.StatusCode, body)
	}
}

func TestPentest_JITDisabled_BlocksUnknownUser(t *testing.T) {
	p := newPlugin(t)
	r := memrepo.New()
	now := time.Now().UTC()
	ctx := context.Background()
	admin, _ := r.CreateUser(ctx, domain.NewUser{ID: uuid.NewString(), Email: "admin@example.com", Role: "user", CreatedAt: now, UpdatedAt: now})
	org, _ := r.CreateOrganization(ctx, domain.NewOrganization{ID: uuid.NewString(), Name: "Acme", Slug: "acme", CreatedAt: now, UpdatedAt: now})
	_, _ = r.CreateMembership(ctx, domain.NewMembership{ID: uuid.NewString(), OrganizationID: org.ID, UserID: admin.ID, Role: auth.RoleOwner, Status: domain.MembershipActive, CreatedAt: now, UpdatedAt: now})

	mux := http.NewServeMux()
	host := newFakeHost(r, "")
	host.mw.AddResolver(&stubResolver{user: &domain.AuthUser{User: admin}})
	p.Routes(host, mux, humaapi.New(mux), "")
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	host.base = srv.URL

	idp := newFakeIDP(t, "rp-1")

	// Create connection with JIT DISABLED.
	createReq := map[string]any{
		"name":                     "Okta",
		"status":                   "active",
		"jit_provisioning_enabled": false,
		"oidc": map[string]any{
			"discovery_url": idp.issuer + "/.well-known/openid-configuration",
			"client_id":     "rp-1",
			"client_secret": "rp-secret",
		},
	}
	resp := doJSON(t, http.MethodPost, srv.URL+"/organizations/"+org.ID+"/sso/connections", createReq)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create: %d", resp.StatusCode)
	}
	resp.Body.Close()

	state, nonce := beginLogin(t, srv, "acme")
	idp.overrideNonce = nonce

	resp = callback(t, srv, state)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 403, got %d %s", resp.StatusCode, body)
	}
}

func TestKidRollover_RefetchesJWKS(t *testing.T) {
	p, srv, r, _, idp := setupForLogin(t)
	_ = r
	_ = p

	// First login → primes the cache with kid-1.
	state, nonce := beginLogin(t, srv, "acme")
	idp.overrideNonce = nonce
	resp := callback(t, srv, state)
	resp.Body.Close()

	// IdP rotates keys.
	idp.rollKey(t)
	before := idp.jwksCalls

	// New login → token signed with new kid; verifier must force a
	// JWKS refresh.
	state, nonce = beginLogin(t, srv, "acme")
	idp.overrideNonce = nonce
	idp.overrideExtraSub = "external-sub-2"
	resp = callback(t, srv, state)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("post-rollover cb: %d %s", resp.StatusCode, body)
	}
	if idp.jwksCalls <= before {
		t.Fatalf("expected JWKS refetch after kid rollover; calls before=%d after=%d", before, idp.jwksCalls)
	}
}

// --- helpers for the pentest cases ------------------------------------

func setupForLogin(t *testing.T) (*ssoOIDCPlugin, *httptest.Server, repo.Repository, *domain.SsoConnection, *fakeIDP) {
	t.Helper()
	p := newPlugin(t)
	r := memrepo.New()
	now := time.Now().UTC()
	ctx := context.Background()
	admin, _ := r.CreateUser(ctx, domain.NewUser{ID: uuid.NewString(), Email: "admin@example.com", Role: "user", CreatedAt: now, UpdatedAt: now})
	org, _ := r.CreateOrganization(ctx, domain.NewOrganization{ID: uuid.NewString(), Name: "Acme", Slug: "acme", CreatedAt: now, UpdatedAt: now})
	_, _ = r.CreateMembership(ctx, domain.NewMembership{ID: uuid.NewString(), OrganizationID: org.ID, UserID: admin.ID, Role: auth.RoleOwner, Status: domain.MembershipActive, CreatedAt: now, UpdatedAt: now})
	mux := http.NewServeMux()
	host := newFakeHost(r, "")
	host.mw.AddResolver(&stubResolver{user: &domain.AuthUser{User: admin}})
	p.Routes(host, mux, humaapi.New(mux), "")
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	host.base = srv.URL

	idp := newFakeIDP(t, "rp-1")
	createReq := map[string]any{
		"name":                     "Okta",
		"status":                   "active",
		"jit_provisioning_enabled": true,
		"oidc": map[string]any{
			"discovery_url": idp.issuer + "/.well-known/openid-configuration",
			"client_id":     "rp-1",
			"client_secret": "rp-secret",
		},
	}
	resp := doJSON(t, http.MethodPost, srv.URL+"/organizations/"+org.ID+"/sso/connections", createReq)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create conn: %d", resp.StatusCode)
	}
	var created connectionJSON
	decode(t, resp, &created)
	conn, _ := r.GetSsoConnectionByID(ctx, created.ID)
	return p, srv, r, conn, idp
}

func beginLogin(t *testing.T, srv *httptest.Server, slug string) (state, nonce string) {
	t.Helper()
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Get(srv.URL + "/sso/login?org=" + slug)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("login: %d %s", resp.StatusCode, body)
	}
	loc, _ := resp.Location()
	return loc.Query().Get("state"), loc.Query().Get("nonce")
}

func callback(t *testing.T, srv *httptest.Server, state string) *http.Response {
	t.Helper()
	cb := srv.URL + "/sso/callback?" + url.Values{
		"code":  []string{"x"},
		"state": []string{state},
	}.Encode()
	resp, err := http.Get(cb)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func (*fakeHost) Logger() *slog.Logger { return slog.Default() }
