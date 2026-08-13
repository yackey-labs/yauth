// Regression suite for OAuth2 token revocation and introspection being
// unbound from the token they act on.
//
// Three related holes, all reachable over the wire on a stock deployment that
// loads the oauth2-server plugin next to bearer:
//
//  1. REVOCATION IS COSMETIC. handleRevoke (plugins/oauth2server/revoke.go)
//     writes a revocation row keyed by the access token's jti via
//     Repo().RevokeToken. The ONLY production reader of Repo().IsTokenRevoked
//     is handleIntrospect (plugins/oauth2server/introspect.go:100). The Bearer
//     credential path — bearerResolver.Resolve in plugins/bearer/resolver.go,
//     which every middleware.RequireAuth / RequireAdmin route goes through —
//     verifies the JWT signature (verifyAccessToken / verifyAsymAccessToken in
//     plugins/bearer/jwt.go) and never consults the revocation list at all. So
//     a relying party can complete RFC 7009 revocation, watch introspection
//     report the token inactive, and the very same token keeps authenticating
//     against every protected route for the remainder of AccessTTL. The one
//     endpoint whose entire purpose is to stop a token working does not.
//
//  2. REVOCATION IS NOT BOUND TO THE CALLING CLIENT. revoke.go binds the
//     REFRESH branch to the authenticated client (`stored.ClientID != nil &&
//     *stored.ClientID == client.ClientID`), but the access-JWT branch
//     authenticates the caller and then never compares it to the token it is
//     about to revoke. Any registered client — including a public one, which
//     authenticates on client_id alone — can write a revocation row for
//     another client's access token. Harmless only for as long as (1) is
//     broken; the moment revocation starts biting, this is a live cross-client
//     kill switch. The two must ship together.
//
//  3. INTROSPECTION LEAKS ANOTHER CLIENT'S SUBJECT. handleIntrospect discards
//     the authenticated client into `_`, and its refresh-token branch answers
//     {"active":true, "sub": <user id>} for a refresh token issued to a
//     completely different client — a cross-client subject disclosure to any
//     registered confidential client that captures or guesses a token.
//
// Each case asserts the thing that matters — the persisted revocation row, or
// the identity actually disclosed in the body — not merely a status code, and
// each is paired with a POSITIVE CONTROL proving the legitimate path still
// works: an unrevoked token still authenticates, a client revoking its OWN
// token still gets the row written, and a client introspecting its OWN refresh
// token still gets active=true with the subject.
package oauth2server_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	yauth "github.com/yackey-labs/yauth"
	"github.com/yackey-labs/yauth/plugins/asymjwt"
	"github.com/yackey-labs/yauth/plugins/bearer"
	"github.com/yackey-labs/yauth/plugins/oauth2server"
	"github.com/yackey-labs/yauth/repo/memrepo"
)

// revocationHarness is the stock oauth2_test harness plus two things it lacks:
// an asymmetric signer (the production OIDC shape — oauth2server then mints
// RS256 access tokens that bearer verifies through verifyAsymAccessToken), and
// an ORDINARY application route protected the way a consumer protects theirs,
// with middleware.RequireAuth. The existing harness only mounts yauth's own
// router, so no test in this package could observe whether a revoked token
// still authenticates; that route is the missing observation point, not a
// parallel harness.
type revocationHarness struct {
	*harness
	resourceURL string
}

func newRevocationHarness(t *testing.T) *revocationHarness {
	t.Helper()
	r := memrepo.New()

	dir := t.TempDir()
	privPath, pubPath := writeServerRSAKeys(t, dir)
	asym, err := asymjwt.New(asymjwt.Config{
		KeyType: "RS256", PrivateKeyPath: privPath, PublicKeyPath: pubPath, KID: "revocation-kid",
	})
	if err != nil {
		t.Fatalf("asymjwt.New: %v", err)
	}

	ya, err := yauth.New(r, yauth.NewDefaultConfig()).
		WithJWTSecret([]byte("test-only-jwt-secret-please-change-32b")).
		WithPlugin(asym).
		WithPlugin(bearer.New(bearer.Config{})).
		WithPlugin(oauth2server.New(oauth2server.Config{
			Issuer:      "http://idp.test",
			BasePath:    "/api/auth",
			AccessTTL:   5 * time.Minute,
			AuthCodeTTL: 1 * time.Minute,
		})).
		Build()
	if err != nil {
		t.Fatalf("build yauth: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/app/resource", ya.Middleware().RequireAuth(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"ok":true}`))
		}),
	))
	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	h := &harness{srv: srv, repo: r}
	return &revocationHarness{harness: h, resourceURL: srv.URL + "/app/resource"}
}

// newConfidentialClient registers a confidential client that can run the
// authorization-code flow and authenticate with client_secret_post.
func (h *revocationHarness) newConfidentialClient(t *testing.T, adminCookie, name, redirectURI string) (clientID, clientSecret string) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"name":                       name,
		"redirect_uris":              []string{redirectURI},
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"scopes":                     []string{"openid", "read"},
		"is_public":                  false,
		"token_endpoint_auth_method": "client_secret_post",
	})
	cid, cs, _ := h.createClient(t, adminCookie, string(body))
	return cid, cs
}

// authorizeCode runs GET /authorize and returns an authorization code,
// handling BOTH shapes that endpoint can answer with.
//
// The shared authorizeAndConsent helper only knows the first-grant shape: a
// consentPayload carrying request_id + csrf_token, which it POSTs back to
// /consent. But on a SECOND grant for the same user+client, authorize.go finds
// the consent row it persisted the first time, consentCovers passes, and it
// mints the code immediately — answering {"redirect_url": "...?code=..."} with
// no request_id at all. Feeding that to authorizeAndConsent POSTs an empty
// request_id and gets a 400. That shape is exactly what the revocation
// positive control needs (a second token for the SAME user and client), so
// this helper reads it rather than avoiding it.
func (h *revocationHarness) authorizeCode(t *testing.T, userCookie, clientID, redirectURI, verifier, state string) string {
	t.Helper()
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", "openid read")
	q.Set("state", state)
	q.Set("code_challenge", pkceS256(verifier))
	q.Set("code_challenge_method", "S256")

	req, _ := http.NewRequest(http.MethodGet, h.srv.URL+"/api/auth/oauth/authorize?"+q.Encode(), nil)
	req.AddCookie(&http.Cookie{Name: "yauth_session", Value: userCookie})
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("authorize: status=%d", res.StatusCode)
	}
	var p struct {
		RequestID   string `json:"request_id"`
		RedirectURL string `json:"redirect_url"`
	}
	if err := json.NewDecoder(res.Body).Decode(&p); err != nil {
		t.Fatalf("decode authorize: %v", err)
	}
	if p.RequestID != "" {
		// First grant: consent has not been recorded yet, so run the full
		// prompt through the shared helper (which repeats the GET — harmless,
		// it is idempotent until consent is stored).
		return h.authorizeAndConsent(t, userCookie, clientID, redirectURI, "openid read", pkceS256(verifier), state, "")
	}
	parsed, err := url.Parse(p.RedirectURL)
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	code := parsed.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in already-consented redirect: %s", p.RedirectURL)
	}
	return code
}

// grantTokens runs a complete authorization-code + PKCE flow and returns the
// access and refresh tokens the client receives.
func (h *revocationHarness) grantTokens(t *testing.T, userCookie, clientID, clientSecret, redirectURI, verifier, state string) (accessToken, refreshToken string) {
	t.Helper()
	code := h.authorizeCode(t, userCookie, clientID, redirectURI, verifier, state)

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	form.Set("code_verifier", verifier)

	status, body := h.postForm(t, "/api/auth/oauth/token", form, "", "")
	if status != http.StatusOK {
		t.Fatalf("token endpoint: status=%d body=%v", status, body)
	}
	at, _ := body["access_token"].(string)
	rt, _ := body["refresh_token"].(string)
	if at == "" || rt == "" {
		t.Fatalf("token endpoint returned no token pair: %v", body)
	}
	return at, rt
}

// resourceStatus calls the ordinary RequireAuth-protected application route
// with the given Bearer token and returns the status code.
func (h *revocationHarness) resourceStatus(t *testing.T, token string) int {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, h.resourceURL, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /app/resource: %v", err)
	}
	defer res.Body.Close()
	return res.StatusCode
}

// revokeAs posts token to the RFC 7009 endpoint as the given client.
func (h *revocationHarness) revokeAs(t *testing.T, clientID, clientSecret, token string) int {
	t.Helper()
	form := url.Values{}
	form.Set("token", token)
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	status, _ := h.postForm(t, "/api/auth/oauth/revoke", form, "", "")
	return status
}

// introspectAs posts token to the RFC 7662 endpoint as the given client.
func (h *revocationHarness) introspectAs(t *testing.T, clientID, clientSecret, token string) map[string]any {
	t.Helper()
	form := url.Values{}
	form.Set("token", token)
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	status, body := h.postForm(t, "/api/auth/oauth/introspect", form, "", "")
	if status != http.StatusOK {
		t.Fatalf("introspect: status=%d body=%v", status, body)
	}
	return body
}

// accessJTI pulls the jti out of an access JWT without verifying it — the test
// needs the same key handleRevoke writes the revocation row under so it can
// assert on the persisted row directly.
func accessJTI(t *testing.T, token string) string {
	t.Helper()
	var claims jwt.MapClaims
	if _, _, err := jwt.NewParser().ParseUnverified(token, &claims); err != nil {
		t.Fatalf("parse access token: %v", err)
	}
	jti, _ := claims["jti"].(string)
	if jti == "" {
		t.Fatalf("access token carries no jti: %v", claims)
	}
	return jti
}

// TestRevokedAccessToken_StopsAuthenticating is defect (1). The client
// completes RFC 7009 revocation of its own access token — the revocation row
// is written and introspection duly reports the token inactive — and the token
// then keeps sailing through middleware.RequireAuth.
func TestRevokedAccessToken_StopsAuthenticating(t *testing.T) {
	h := newRevocationHarness(t)
	_, adminCookie := h.seedUser(t, "admin@idp.test", "admin")
	_, userCookie := h.seedUser(t, "alice@idp.test", "user")

	const redirectURI = "https://app.example/callback"
	clientID, clientSecret := h.newConfidentialClient(t, adminCookie, "demo", redirectURI)

	accessToken, _ := h.grantTokens(t, userCookie, clientID, clientSecret,
		redirectURI, "revocation-verifier-is-43-characters-long-ok", "s1")

	// Baseline: the fresh token authenticates.
	if got := h.resourceStatus(t, accessToken); got != http.StatusOK {
		t.Fatalf("pre-revocation: protected route should accept a fresh access token, got %d", got)
	}

	if got := h.revokeAs(t, clientID, clientSecret, accessToken); got != http.StatusOK {
		t.Fatalf("revoke: status=%d, want 200", got)
	}

	// The revocation really was recorded — this is not a test of the revoke
	// endpoint failing to write. Both the stored row and the endpoint that
	// reads it agree the token is dead.
	jti := accessJTI(t, accessToken)
	revoked, err := h.repo.IsTokenRevoked(context.Background(), jti)
	if err != nil {
		t.Fatalf("IsTokenRevoked: %v", err)
	}
	if !revoked {
		t.Fatalf("revoke wrote no revocation row for jti %s — precondition for this test failed", jti)
	}
	if body := h.introspectAs(t, clientID, clientSecret, accessToken); body["active"] != false {
		t.Fatalf("introspection should report the revoked token inactive, got %v", body)
	}

	// THE DEFECT: the revoked token still authenticates on every RequireAuth
	// route, because bearerResolver.Resolve never consults the revocation list.
	if got := h.resourceStatus(t, accessToken); got != http.StatusUnauthorized {
		t.Fatalf("revoked access token STILL authenticates: GET /app/resource returned %d, want 401", got)
	}

	// POSITIVE CONTROL: revocation is per-token, not a blanket break. A second
	// token from a second grant — never revoked — must keep working.
	fresh, _ := h.grantTokens(t, userCookie, clientID, clientSecret,
		redirectURI, "second-grant-verifier-also-43-chars-long-x", "s2")
	if got := h.resourceStatus(t, fresh); got != http.StatusOK {
		t.Fatalf("positive control: an unrevoked access token must still authenticate, got %d", got)
	}
}

// TestFirstPartyBearerToken_Unaffected is the guard the revocation lookup must
// not break: a first-party bearer credential (token_use=yauth_access), for
// which nothing writes revocation rows today, keeps authenticating.
func TestFirstPartyBearerToken_Unaffected(t *testing.T) {
	h := newRevocationHarness(t)
	uid, _ := h.seedUser(t, "carol@idp.test", "user")

	now := time.Now().UTC()
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss":       "yauth", // bearer.Config default issuer
		"sub":       uid,
		"jti":       "first-party-jti-with-no-revocation-row",
		"iat":       now.Unix(),
		"nbf":       now.Unix(),
		"exp":       now.Add(15 * time.Minute).Unix(),
		"token_use": "yauth_access",
	}).SignedString([]byte("test-only-jwt-secret-please-change-32b"))
	if err != nil {
		t.Fatalf("sign first-party token: %v", err)
	}

	if got := h.resourceStatus(t, tok); got != http.StatusOK {
		t.Fatalf("first-party bearer token must still authenticate, got %d", got)
	}
}

// TestRevokeAccessToken_ForeignClient_Ignored is defect (2). Client B — which
// never received A's token and has nothing to do with A's grant — hands A's
// access token to /oauth/revoke with its own credentials, and the server
// writes the revocation row anyway. Asserted on the PERSISTED ROW rather than
// on whether the token still authenticates, so the case stands on its own
// while defect (1) is unfixed and keeps standing once it is fixed.
func TestRevokeAccessToken_ForeignClient_Ignored(t *testing.T) {
	h := newRevocationHarness(t)
	_, adminCookie := h.seedUser(t, "admin@idp.test", "admin")
	_, userCookie := h.seedUser(t, "alice@idp.test", "user")

	clientA, secretA := h.newConfidentialClient(t, adminCookie, "app-a", "https://a.example/callback")
	clientB, secretB := h.newConfidentialClient(t, adminCookie, "app-b", "https://b.example/callback")

	tokenA, _ := h.grantTokens(t, userCookie, clientA, secretA,
		"https://a.example/callback", "client-a-verifier-is-43-characters-long-abc", "a1")
	jtiA := accessJTI(t, tokenA)

	// B revokes A's token. RFC 7009 §2.1 requires the server to verify the
	// token was issued to the client making the request; an unowned token is
	// "unknown" — still 200, but nothing revoked.
	if got := h.revokeAs(t, clientB, secretB, tokenA); got != http.StatusOK {
		t.Fatalf("foreign revoke: status=%d, want 200 (idempotent)", got)
	}

	revoked, err := h.repo.IsTokenRevoked(context.Background(), jtiA)
	if err != nil {
		t.Fatalf("IsTokenRevoked: %v", err)
	}
	if revoked {
		t.Fatalf("client B revoked client A's access token: a revocation row exists for jti %s", jtiA)
	}

	// POSITIVE CONTROL: A revoking its OWN token still works — the binding must
	// not disable revocation outright.
	if got := h.revokeAs(t, clientA, secretA, tokenA); got != http.StatusOK {
		t.Fatalf("self revoke: status=%d, want 200", got)
	}
	revoked, err = h.repo.IsTokenRevoked(context.Background(), jtiA)
	if err != nil {
		t.Fatalf("IsTokenRevoked: %v", err)
	}
	if !revoked {
		t.Fatalf("positive control: a client must still be able to revoke its own access token (no row for jti %s)", jtiA)
	}
}

// TestIntrospect_ForeignRefreshToken_Inactive is defect (3). Client B
// introspects a refresh token issued to client A and is told active=true plus
// the resource owner's user id — a cross-client subject disclosure.
func TestIntrospect_ForeignRefreshToken_Inactive(t *testing.T) {
	h := newRevocationHarness(t)
	_, adminCookie := h.seedUser(t, "admin@idp.test", "admin")
	aliceID, userCookie := h.seedUser(t, "alice@idp.test", "user")

	clientA, secretA := h.newConfidentialClient(t, adminCookie, "app-a", "https://a.example/callback")
	clientB, secretB := h.newConfidentialClient(t, adminCookie, "app-b", "https://b.example/callback")

	_, refreshA := h.grantTokens(t, userCookie, clientA, secretA,
		"https://a.example/callback", "introspect-verifier-is-43-chars-long-okay-y", "i1")

	// POSITIVE CONTROL first: A introspecting its own refresh token is the
	// legitimate use of this endpoint and must keep answering active=true with
	// the subject.
	own := h.introspectAs(t, clientA, secretA, refreshA)
	if own["active"] != true {
		t.Fatalf("positive control: client A must be able to introspect its own refresh token, got %v", own)
	}
	if own["sub"] != aliceID {
		t.Fatalf("positive control: own introspection should report sub=%s, got %v", aliceID, own["sub"])
	}

	// THE DEFECT: B gets the same answer for a token that was never issued to
	// it, learning both that the token is live and whose it is.
	foreign := h.introspectAs(t, clientB, secretB, refreshA)
	if foreign["active"] != false {
		t.Fatalf("client B introspected client A's refresh token and got active=true (sub=%v): %v", foreign["sub"], foreign)
	}
	if foreign["sub"] != nil {
		t.Fatalf("client B learned the subject of client A's refresh token: sub=%v", foreign["sub"])
	}
}
