package oauth2server_test

// private_key_jwt (RFC 7523) is the credential a machine-to-machine client
// presents at POST /oauth/token instead of a shared secret: a short-lived JWT
// the client signs with its own private key. The whole point of the scheme is
// that the assertion is a ONE-TIME, SINGLE-AUDIENCE bearer credential — RFC 7523
// §3 rule 3 requires the authorization server to reject an assertion whose "aud"
// names some OTHER server, and rule 7 lets it reject a replayed "jti".
//
// oauth2server.verifyPrivateKeyJWT (plugins/oauth2server/client_auth.go) does
// neither. The verifying re-parse asks jwt.Parse for WithValidMethods,
// WithIssuer(clientID) and WithExpirationRequired — and nothing else. "aud" is
// never read; "jti" appears nowhere in the package. Three concrete consequences,
// all reachable over HTTP through authenticateClient → the token endpoint:
//
//  1. Cross-AS credential forwarding. A client that uses one keypair at two
//     authorization servers — the ordinary M2M federation shape — signs an
//     assertion for server B. Whoever holds that assertion (server B itself, or
//     anyone who can read B's request logs) POSTs it verbatim to THIS server and
//     is authenticated as that client here.
//  2. Unlimited replay until exp. A captured assertion (proxy log, APM trace, an
//     error report echoing the form body) is redeemable over and over.
//  3. An unadvertised second credential path. authenticateClient enters
//     verifyPrivateKeyJWT purely on the client_assertion_type form field, BEFORE
//     the client's registered token_endpoint_auth_method is ever consulted, so a
//     client registered client_secret_basic that also carries a public_key_pem
//     can authenticate by assertion — and rotating its client secret does not
//     close that door.
//
// Each refusal below is paired with a positive control so a future fix cannot
// pass by breaking private_key_jwt outright: an assertion whose aud is the
// issuer, and one whose aud is the advertised token endpoint, must both keep
// authenticating, and the secret-basic client must keep authenticating by secret.

import (
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// pkjwtIssuer / pkjwtTokenEndpoint are the two audience values this deployment
// legitimately answers to: Config.Issuer as handed to newPKJWTHarness, and the
// token_endpoint the RFC 8414 metadata document advertises (metadata.go builds
// it as TrimRight(Issuer,"/") + TrimRight(BasePath,"/") + "/oauth/token").
const (
	pkjwtIssuer        = "http://idp.test"
	pkjwtTokenEndpoint = "http://idp.test/api/auth/oauth/token"
)

// signPKJWTAssertionWithJTI is signPKJWTAssertion with the jti pinned by the
// caller, so a test can hand the same logical assertion to the endpoint twice
// (replay) or omit the claim entirely (jti == "").
func signPKJWTAssertionWithJTI(t *testing.T, k *rsa.PrivateKey, clientID, audience, jti string) string {
	t.Helper()
	now := time.Now().UTC()
	claims := jwt.MapClaims{
		"iss": clientID,
		"sub": clientID,
		"aud": audience,
		"iat": now.Unix(),
		"exp": now.Add(2 * time.Minute).Unix(),
	}
	if jti != "" {
		claims["jti"] = jti
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signed, err := tok.SignedString(k)
	if err != nil {
		t.Fatalf("sign assertion: %v", err)
	}
	return signed
}

// newPKJWTClient registers a confidential client_credentials client with the
// given token_endpoint_auth_method and a registered public key, and returns the
// client_id, its one-time secret, and the private key its assertions are signed
// with.
func newPKJWTClient(t *testing.T, h *pkjwtHarness, adminCookie, authMethod string) (clientID, secret string, key *rsa.PrivateKey) {
	t.Helper()
	key, pubPEM := makeClientRSA(t)
	body, _ := json.Marshal(map[string]any{
		"name":                       "pkjwt-" + authMethod,
		"redirect_uris":              []string{},
		"grant_types":                []string{"client_credentials"},
		"scopes":                     []string{"read"},
		"is_public":                  false,
		"token_endpoint_auth_method": authMethod,
		"public_key_pem":             pubPEM,
	})
	clientID, secret, _ = h.createClient(t, adminCookie, string(body))
	return clientID, secret, key
}

// postAssertion presents assertion at the token endpoint as a
// client_credentials request.
func postAssertion(t *testing.T, h *pkjwtHarness, clientID, assertion string) (int, map[string]any) {
	t.Helper()
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", clientID)
	form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	form.Set("client_assertion", assertion)
	form.Set("scope", "read")
	return h.postForm(t, "/api/auth/oauth/token", form, "", "")
}

// TestPrivateKeyJWT_WrongAudienceRejected is the RFC 7523 §3 rule-3 check: an
// assertion minted for a DIFFERENT authorization server must not authenticate
// here, while an assertion minted for this one still must.
func TestPrivateKeyJWT_WrongAudienceRejected(t *testing.T) {
	h := newPKJWTHarness(t)
	_, adminCookie := h.seedUser(t, "admin@idp.test", "admin")
	clientID, _, key := newPKJWTClient(t, h, adminCookie, "private_key_jwt")

	// POSITIVE CONTROL 1 — aud is the issuer this AS publishes.
	status, body := postAssertion(t, h, clientID, signPKJWTAssertionWithJTI(t, key, clientID, pkjwtIssuer, uuid.NewString()))
	if status != http.StatusOK {
		t.Fatalf("aud=issuer must authenticate: status=%d body=%v", status, body)
	}
	if _, ok := body["access_token"]; !ok {
		t.Fatalf("aud=issuer: no access_token in %v", body)
	}

	// POSITIVE CONTROL 2 — aud is the token_endpoint from the RFC 8414 doc.
	status, body = postAssertion(t, h, clientID, signPKJWTAssertionWithJTI(t, key, clientID, pkjwtTokenEndpoint, uuid.NewString()))
	if status != http.StatusOK {
		t.Fatalf("aud=token_endpoint must authenticate: status=%d body=%v", status, body)
	}
	if _, ok := body["access_token"]; !ok {
		t.Fatalf("aud=token_endpoint: no access_token in %v", body)
	}

	// THE DEFECT — the same client's assertion, minted for somebody else's
	// authorization server, is forwarded here verbatim.
	foreign := signPKJWTAssertionWithJTI(t, key, clientID, "https://attacker-as.example/oauth/token", uuid.NewString())
	status, body = postAssertion(t, h, clientID, foreign)
	if _, minted := body["access_token"]; minted {
		t.Fatalf("an assertion with aud=https://attacker-as.example/oauth/token minted an access token here: status=%d body=%v", status, body)
	}
	if body["error"] != "invalid_client" {
		t.Fatalf("expected error=invalid_client for a foreign audience, got status=%d body=%v", status, body)
	}
}

// TestPrivateKeyJWT_ReplayRejected proves the assertion is one-time: the same
// signed string presented twice must authenticate at most once.
func TestPrivateKeyJWT_ReplayRejected(t *testing.T) {
	h := newPKJWTHarness(t)
	_, adminCookie := h.seedUser(t, "admin@idp.test", "admin")
	clientID, _, key := newPKJWTClient(t, h, adminCookie, "private_key_jwt")

	assertion := signPKJWTAssertionWithJTI(t, key, clientID, pkjwtTokenEndpoint, uuid.NewString())

	status, body := postAssertion(t, h, clientID, assertion)
	if status != http.StatusOK {
		t.Fatalf("first presentation must succeed: status=%d body=%v", status, body)
	}

	// THE DEFECT — byte-identical replay.
	status, body = postAssertion(t, h, clientID, assertion)
	if _, minted := body["access_token"]; minted {
		t.Fatalf("a replayed client_assertion minted a second access token: status=%d body=%v", status, body)
	}
	if body["error"] != "invalid_client" {
		t.Fatalf("expected error=invalid_client on replay, got status=%d body=%v", status, body)
	}

	// POSITIVE CONTROL — a FRESH assertion (new jti) from the same client must
	// still work, so the replay defence cannot be "reject everything after the
	// first request".
	status, body = postAssertion(t, h, clientID, signPKJWTAssertionWithJTI(t, key, clientID, pkjwtTokenEndpoint, uuid.NewString()))
	if status != http.StatusOK {
		t.Fatalf("a fresh assertion must still authenticate after a replay rejection: status=%d body=%v", status, body)
	}
	if _, ok := body["access_token"]; !ok {
		t.Fatalf("fresh assertion: no access_token in %v", body)
	}
}

// TestPrivateKeyJWT_MissingJTIRejected: without a jti there is nothing to record,
// so the assertion is unconditionally replayable and must be refused.
func TestPrivateKeyJWT_MissingJTIRejected(t *testing.T) {
	h := newPKJWTHarness(t)
	_, adminCookie := h.seedUser(t, "admin@idp.test", "admin")
	clientID, _, key := newPKJWTClient(t, h, adminCookie, "private_key_jwt")

	status, body := postAssertion(t, h, clientID, signPKJWTAssertionWithJTI(t, key, clientID, pkjwtTokenEndpoint, ""))
	if _, minted := body["access_token"]; minted {
		t.Fatalf("a client_assertion with no jti minted an access token: status=%d body=%v", status, body)
	}
	if body["error"] != "invalid_client" {
		t.Fatalf("expected error=invalid_client for a jti-less assertion, got status=%d body=%v", status, body)
	}
}

// TestPrivateKeyJWT_RefusedForSecretBasicClient proves the assertion path is not
// a second, unadvertised credential for a client that registered a secret. The
// registered token_endpoint_auth_method is the contract; an operator who rotates
// the secret expects that to be the whole credential surface.
func TestPrivateKeyJWT_RefusedForSecretBasicClient(t *testing.T) {
	h := newPKJWTHarness(t)
	_, adminCookie := h.seedUser(t, "admin@idp.test", "admin")
	clientID, secret, key := newPKJWTClient(t, h, adminCookie, "client_secret_basic")

	// POSITIVE CONTROL — the method the client actually registered still works.
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("scope", "read")
	status, body := h.postForm(t, "/api/auth/oauth/token", form, clientID, secret)
	if status != http.StatusOK {
		t.Fatalf("client_secret_basic must keep authenticating: status=%d body=%v", status, body)
	}

	// THE DEFECT — the same client authenticates by assertion, a credential path
	// it never registered for.
	status, body = postAssertion(t, h, clientID, signPKJWTAssertionWithJTI(t, key, clientID, pkjwtTokenEndpoint, uuid.NewString()))
	if _, minted := body["access_token"]; minted {
		t.Fatalf("a client registered client_secret_basic authenticated by private_key_jwt assertion: status=%d body=%v", status, body)
	}
	if body["error"] != "invalid_client" {
		t.Fatalf("expected error=invalid_client for an assertion from a client_secret_basic client, got status=%d body=%v", status, body)
	}
}
