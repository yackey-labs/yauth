// Regression suite for OAuth2 scope escalation.
//
// grantRefreshToken took the requested scope on trust — `splitScopes(f.Scope)`,
// falling back to the client's REGISTERED scopes — and compared it against
// nothing. RFC 6749 §6 says a refresh request's scope "MUST NOT include any
// scope not originally granted by the resource owner", and the grant was not
// recorded anywhere that survived the authorization code being consumed. So a
// user who consented to "openid" could have that client refresh into
// "openid groups admin billing:write", receive an access token whose `scope`
// claim said exactly that, and an id_token whose "groups" claim (gated on the
// groups scope) carried membership that was never consented to. /oauth/authorize
// never checked the requested scope against the client's registration either,
// so scope was self-asserted from the first step of the flow.
//
// Each case asserts the REFUSAL at the level that matters — the escalated
// scope absent from the ISSUED TOKEN's claims, not merely a differing response
// field — and pairs it with a positive control so a future "fix" cannot pass by
// breaking refresh outright.
//
// The shared harness lives in security_refresh_issuer_test.go.
package yauth_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/yackey-labs/yauth/auth"
	"github.com/yackey-labs/yauth/domain"
)

// scopeClaimOf parses an unverified JWT and returns its claims. The signature
// is checked by the server that issued it; here we only care what it SAYS.
func scopeClaimsOf(t *testing.T, what, token string) jwt.MapClaims {
	t.Helper()
	if token == "" {
		t.Fatalf("%s: empty token", what)
	}
	parsed, _, err := jwt.NewParser().ParseUnverified(token, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("%s: parse: %v", what, err)
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatalf("%s: unexpected claims type", what)
	}
	return claims
}

// scopeTokenResponse is the subset of the RFC 6749 §5.1 body these cases read.
type scopeTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	Scope        string `json:"scope"`
}

func decodeScopeTokens(t *testing.T, what string, body []byte) scopeTokenResponse {
	t.Helper()
	var out scopeTokenResponse
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("%s: decode %s: %v", what, body, err)
	}
	return out
}

// A refresh request must not widen the grant. The user consented to "openid";
// asking for "openid groups admin billing:write" on the refresh is refused,
// and — the part that actually matters — no token carrying those scopes is
// issued at all.
func TestRefreshGrant_ScopeEscalationRefused(t *testing.T) {
	h := newOAuth2Harness(t)
	uid := secRegister(t, h, "victim-scope@test.local")
	secSeedClient(t, h, "scope-app")
	rt := secClientRefreshToken(t, h, "scope-app", uid, "ac-scope")

	code, body := secPostForm(t, h.url("/oauth/token"), url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {rt},
		"client_id":     {"scope-app"},
		"scope":         {"openid groups admin billing:write"},
	})
	if code != http.StatusBadRequest {
		t.Fatalf("refresh grant honoured an escalated scope: %d %s", code, body)
	}
	if !strings.Contains(string(body), "invalid_scope") {
		t.Fatalf("expected an invalid_scope error, got: %s", body)
	}
	// Nothing may be minted on the refused exchange — not an access token
	// carrying the escalated scope, and not the id_token that came with it.
	secAssertNoToken(t, "escalated refresh", body)

	// Positive control: the SAME token still refreshes for what was granted,
	// so the refusal above is the scope check and not a broken refresh path.
	code, body = secPostForm(t, h.url("/oauth/token"), url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {rt},
		"client_id":     {"scope-app"},
	})
	if code != http.StatusOK {
		t.Fatalf("the granted scope no longer refreshes: %d %s", code, body)
	}
	tok := decodeScopeTokens(t, "granted refresh", body)
	if tok.Scope != "openid" {
		t.Fatalf("refresh returned scope %q, want the granted %q", tok.Scope, "openid")
	}
	// The claim inside the ISSUED access token, not the response field.
	claims := scopeClaimsOf(t, "access token", tok.AccessToken)
	got, _ := claims["scope"].(string)
	if got != "openid" {
		t.Fatalf("access token scope claim = %q, want %q", got, "openid")
	}
	for _, forbidden := range []string{"groups", "admin", "billing:write"} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("access token carries the never-granted scope %q: %q", forbidden, got)
		}
	}
	// And the id_token: the "groups" claim is gated on the groups scope, so
	// an escalation here leaks group membership the user never consented to.
	idClaims := scopeClaimsOf(t, "id_token", tok.IDToken)
	if _, ok := idClaims["groups"]; ok {
		t.Fatalf("id_token carries a groups claim the user never granted: %v", idClaims["groups"])
	}
}

// The escalated scope must not reach the token even when the refused exchange
// is retried after a legitimate one — i.e. the recorded grant is what binds,
// not some in-memory state of the first request.
func TestRefreshGrant_ScopeCeilingSurvivesRotation(t *testing.T) {
	h := newOAuth2Harness(t)
	uid := secRegister(t, h, "victim-rotate@test.local")
	secSeedClient(t, h, "rotate-app")
	rt := secClientRefreshToken(t, h, "rotate-app", uid, "ac-rotate")

	// Rotate legitimately a couple of times; each rotation must carry the
	// grant forward onto the new row.
	for i := range 2 {
		code, body := secPostForm(t, h.url("/oauth/token"), url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {rt},
			"client_id":     {"rotate-app"},
		})
		if code != http.StatusOK {
			t.Fatalf("rotation %d: %d %s", i, code, body)
		}
		tok := decodeScopeTokens(t, "rotation", body)
		if tok.RefreshToken == "" {
			t.Fatalf("rotation %d returned no refresh token: %s", i, body)
		}
		rt = tok.RefreshToken
	}

	code, body := secPostForm(t, h.url("/oauth/token"), url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {rt},
		"client_id":     {"rotate-app"},
		"scope":         {"openid admin"},
	})
	if code != http.StatusBadRequest {
		t.Fatalf("the grant ceiling was lost across rotation: %d %s", code, body)
	}
	secAssertNoToken(t, "escalation after rotation", body)
}

// A client may legitimately ask for LESS than it holds (RFC 6749 §6), and
// doing so must not forfeit the rest of the grant on the next exchange — the
// rotated row keeps the original grant, only the issued token narrows.
func TestRefreshGrant_DownScopeDoesNotForfeitTheGrant(t *testing.T) {
	h := newOAuth2Harness(t)
	uid := secRegister(t, h, "victim-downscope@test.local")

	// A client and a code granting two scopes, so there is something to
	// narrow away from.
	if err := h.repo.CreateOAuth2Client(context.Background(), domain.NewOAuth2Client{
		ID:           "c-narrow-app",
		ClientID:     "narrow-app",
		RedirectURIs: secRawJSON([]string{"https://third-party.example/cb"}),
		GrantTypes:   secRawJSON([]string{"authorization_code", "refresh_token"}),
		Scopes:       secRawJSON([]string{"openid", "read"}),
		IsPublic:     true,
		CreatedAt:    time.Now().UTC(),
	}); err != nil {
		t.Fatalf("create client: %v", err)
	}
	verifier := "verifier-verifier-verifier-verifier-0123"
	rawCode := "authcode-narrow"
	if err := h.repo.CreateAuthorizationCode(context.Background(), domain.NewAuthorizationCode{
		ID:                  "ac-narrow",
		CodeHash:            auth.HashToken(rawCode),
		ClientID:            "narrow-app",
		UserID:              uid,
		Scopes:              secRawJSON([]string{"openid", "read"}),
		RedirectURI:         "https://third-party.example/cb",
		CodeChallenge:       secS256(verifier),
		CodeChallengeMethod: "S256",
		ExpiresAt:           time.Now().UTC().Add(time.Minute),
		CreatedAt:           time.Now().UTC(),
	}); err != nil {
		t.Fatalf("seed auth code: %v", err)
	}
	code, body := secPostForm(t, h.url("/oauth/token"), url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {rawCode},
		"redirect_uri":  {"https://third-party.example/cb"},
		"code_verifier": {verifier},
		"client_id":     {"narrow-app"},
	})
	if code != http.StatusOK {
		t.Fatalf("authorization_code exchange: %d %s", code, body)
	}
	rt := decodeScopeTokens(t, "auth code", body).RefreshToken

	// Refresh asking for only "read".
	code, body = secPostForm(t, h.url("/oauth/token"), url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {rt},
		"client_id":     {"narrow-app"},
		"scope":         {"read"},
	})
	if code != http.StatusOK {
		t.Fatalf("down-scoped refresh refused: %d %s", code, body)
	}
	tok := decodeScopeTokens(t, "down-scoped refresh", body)
	if tok.Scope != "read" {
		t.Fatalf("down-scoped refresh returned scope %q, want %q", tok.Scope, "read")
	}
	claims := scopeClaimsOf(t, "down-scoped access token", tok.AccessToken)
	if got, _ := claims["scope"].(string); got != "read" {
		t.Fatalf("access token scope claim = %q, want %q", got, "read")
	}
	// openid was not requested, so no id_token this time.
	if tok.IDToken != "" {
		t.Fatalf("down-scoped refresh emitted an id_token without the openid scope")
	}

	// The next refresh can still reach the full grant: narrowing once is not
	// a permanent forfeit.
	code, body = secPostForm(t, h.url("/oauth/token"), url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {tok.RefreshToken},
		"client_id":     {"narrow-app"},
		"scope":         {"openid read"},
	})
	if code != http.StatusOK {
		t.Fatalf("a down-scoped refresh forfeited the rest of the grant: %d %s", code, body)
	}
	if got := decodeScopeTokens(t, "rewidened refresh", body).Scope; got != "openid read" {
		t.Fatalf("re-widening within the grant returned scope %q", got)
	}
}

// A row written before migration 010 records no grant. It must not be refused
// (that would sign out live integrations at the deploy) and must not be handed
// the request either (that is the hole). The grant is reconstructed from the
// user's consent record.
func TestRefreshGrant_PreMigrationRowFallsBackToConsent(t *testing.T) {
	h := newOAuth2Harness(t)
	ctx := context.Background()
	uid := secRegister(t, h, "victim-legacy@test.local")
	secSeedClient(t, h, "legacy-app")

	// The consent the user actually gave.
	if err := h.repo.CreateConsent(ctx, domain.NewConsent{
		ID: "consent-legacy", UserID: uid, ClientID: "legacy-app",
		Scopes:    secRawJSON([]string{"openid"}),
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("seed consent: %v", err)
	}
	// A row exactly as the code between migrations 009 and 010 wrote it:
	// client stamped, grant not recorded.
	raw := "legacy-oauth2-refresh-token-no-recorded-scopes"
	clientID := "legacy-app"
	if err := h.repo.CreateRefreshToken(ctx, domain.NewRefreshToken{
		ID:        "legacy-scope-rt",
		UserID:    uid,
		TokenHash: auth.HashToken(raw),
		FamilyID:  "legacy-scope-family",
		ClientID:  &clientID,
		ExpiresAt: time.Now().UTC().Add(24 * time.Hour),
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("seed legacy refresh token: %v", err)
	}

	// It still works — for the consented scope.
	code, body := secPostForm(t, h.url("/oauth/token"), url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {raw},
		"client_id":     {"legacy-app"},
	})
	if code != http.StatusOK {
		t.Fatalf("a pre-migration OAuth2 refresh token was rejected: %d %s", code, body)
	}
	tok := decodeScopeTokens(t, "legacy refresh", body)
	if tok.Scope != "openid" {
		t.Fatalf("legacy refresh returned scope %q, want the consented %q", tok.Scope, "openid")
	}

	// And it is NOT a way back into the hole: the request is still capped by
	// the reconstructed grant.
	code, body = secPostForm(t, h.url("/oauth/token"), url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {tok.RefreshToken},
		"client_id":     {"legacy-app"},
		"scope":         {"openid admin"},
	})
	if code != http.StatusBadRequest {
		t.Fatalf("a pre-migration row let the request set its own scope: %d %s", code, body)
	}
	secAssertNoToken(t, "escalation on a pre-migration row", body)
}

// /authorize let the client name any scope it liked; only the consent prompt
// bounded it. A scope outside the client's registration is now refused before
// a code — and therefore a grant — exists.
func TestAuthorize_ScopeOutsideClientRegistrationRefused(t *testing.T) {
	h := newOAuth2Harness(t)
	ctx := context.Background()
	uid := secRegister(t, h, "victim-authz@test.local")
	secSeedClient(t, h, "authz-app") // registered for "openid" only

	// A session cookie for the /authorize call, which is an authenticated
	// route.
	raw, _, err := auth.IssueSession(ctx, h.repo, uid, nil, nil, time.Hour)
	if err != nil {
		t.Fatalf("issue session: %v", err)
	}

	getAuthorize := func(scope string) (int, string) {
		t.Helper()
		q := url.Values{}
		q.Set("response_type", "code")
		q.Set("client_id", "authz-app")
		q.Set("redirect_uri", "https://third-party.example/cb")
		q.Set("scope", scope)
		q.Set("code_challenge", secS256("verifier-verifier-verifier-verifier-0123"))
		q.Set("code_challenge_method", "S256")
		req, _ := http.NewRequest(http.MethodGet, h.url("/oauth/authorize?"+q.Encode()), nil)
		req.AddCookie(&http.Cookie{Name: "yauth_session", Value: raw})
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("authorize: %v", err)
		}
		defer func() { _ = res.Body.Close() }()
		buf := make([]byte, 4096)
		n, _ := res.Body.Read(buf)
		return res.StatusCode, string(buf[:n])
	}

	status, body := getAuthorize("openid admin billing:write")
	if status == http.StatusOK {
		t.Fatalf("/authorize accepted a scope the client is not registered for: %s", body)
	}
	if !strings.Contains(body, "invalid_scope") {
		t.Fatalf("expected an invalid_scope error, got %d %s", status, body)
	}

	// Positive control: the registered scope still reaches the consent step.
	status, body = getAuthorize("openid")
	if status != http.StatusOK {
		t.Fatalf("/authorize refused the client's own registered scope: %d %s", status, body)
	}
}
