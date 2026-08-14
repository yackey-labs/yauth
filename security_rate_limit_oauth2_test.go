// Regression suite for the UNMETERED OAuth2 wire endpoints.
//
// oauth2server registers POST /oauth/token, /oauth/introspect, /oauth/revoke
// and /oauth/device/code with `public := stashOnly(api)`
// (plugins/oauth2server/routes_huma.go) — a middleware chain that is nothing
// but StashHTTPHuma. There is no RateLimitFor anywhere in the plugin, and
// yauth.Router() wraps the mux only in SecurityHeaders, so no limiter sits in
// front of these four routes at any layer. The plugin's own Config doc comment
// says so out loud: "yauth-go does not rate-limit /oauth/token,
// /oauth/introspect, or /oauth/device/code either".
//
// Three of the four funnel straight into oauth2Plugin.authenticateClient
// (client_auth.go), which for a confidential client on client_secret_post /
// client_secret_basic reaches secretMatches -> auth.VerifyPassword ->
// argon2.IDKey with m=64MiB, t=1, p=4 (auth/password.go). The only input the
// caller needs is a client_id, which is public by construction — it appears in
// every /authorize URL, every RFC 7591 registration response and the RFC 8414
// metadata document. So an anonymous caller can pin 64 MiB of RSS per in-flight
// request for as long as it likes, and can guess client secrets without a
// ceiling while doing it.
//
// These tests assert the WORK is bounded, not the RSS: the repository lookup
// that immediately precedes the argon2 verify is counted, because for a
// confidential client with a stored secret hash that lookup is followed
// unconditionally by exactly one 64 MiB hash. A limiter registered anywhere
// but OUTERMOST in the huma chain would still let that work happen, so the
// counter — not the status code — is what pins the fix.
//
// Every refusal here is paired with a positive control from a different client
// IP, so a "fix" that simply breaks the token endpoint, or that meters the
// whole world into one shared bucket, cannot pass.
package yauth_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	yauth "github.com/yackey-labs/yauth"
	"github.com/yackey-labs/yauth/auth"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/plugins/oauth2server"
	"github.com/yackey-labs/yauth/repo"
	"github.com/yackey-labs/yauth/repo/memrepo"
)

// meterRepo counts the client lookup that gates the argon2 verify.
//
// GetOAuth2ClientByClientID is the last thing that happens before
// secretMatches on the client_secret_post / client_secret_basic paths, so for
// a confidential client whose ClientSecretHash is set, one increment here is
// one 64 MiB argon2id computation.
type meterRepo struct {
	repo.Repository
	clientLookups atomic.Int64
}

func (m *meterRepo) GetOAuth2ClientByClientID(ctx context.Context, clientID string) (*domain.OAuth2Client, error) {
	m.clientLookups.Add(1)
	return m.Repository.GetOAuth2ClientByClientID(ctx, clientID)
}

const (
	oauthMeterClientID = "meter-app"
	oauthMeterSecret   = "s3cr3t-machine-credential-for-tests"
)

type oauthMeterHarness struct {
	srv  *httptest.Server
	repo *meterRepo
}

func (h *oauthMeterHarness) url(path string) string { return h.srv.URL + "/api/auth" + path }

// newOAuthMeterHarness boots a server carrying only oauth2server, with the
// SHIPPED default configuration — the deployment an operator gets by writing
// nothing at all under rate_limit in yauth.yaml. One confidential client is
// seeded, registered for the client_credentials and device_code grants and
// authenticating with a real argon2id secret hash.
func newOAuthMeterHarness(t *testing.T) *oauthMeterHarness {
	t.Helper()

	r := &meterRepo{Repository: memrepo.New()}
	ya, err := yauth.New(r, yauth.NewDefaultConfig()).
		WithJWTSecret([]byte(secJWTSecret)).
		WithPlugin(oauth2server.New(oauth2server.Config{
			Issuer:      "http://idp.test",
			BasePath:    "/api/auth",
			AuthCodeTTL: time.Minute,
			AccessTTL:   15 * time.Minute,
			RefreshTTL:  24 * time.Hour,
		})).
		Build()
	if err != nil {
		t.Fatalf("build yauth: %v", err)
	}

	hash, err := auth.HashPassword(oauthMeterSecret)
	if err != nil {
		t.Fatalf("hash client secret: %v", err)
	}
	method := "client_secret_post"
	if err := r.CreateOAuth2Client(context.Background(), domain.NewOAuth2Client{
		ID:               "c-" + oauthMeterClientID,
		ClientID:         oauthMeterClientID,
		ClientSecretHash: &hash,
		RedirectURIs:     secRawJSON([]string{"https://rp.example/cb"}),
		GrantTypes: secRawJSON([]string{
			"client_credentials",
			"refresh_token",
			"urn:ietf:params:oauth:grant-type:device_code",
		}),
		Scopes:                  secRawJSON([]string{"api"}),
		TokenEndpointAuthMethod: &method,
		IsPublic:                false,
		CreatedAt:               time.Now().UTC(),
	}); err != nil {
		t.Fatalf("create client: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &oauthMeterHarness{srv: srv, repo: r}
}

// meterPost posts a form as clientIP. httptest's peer is 127.0.0.1, which the
// default trusted-proxy policy trusts, so X-Forwarded-For stands in for a
// proxied client exactly as it does in security_rate_limit_test.go.
func meterPost(t *testing.T, h *oauthMeterHarness, path, clientIP string, form url.Values) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, h.url(path), strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Forwarded-For", clientIP)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post %s: %v", path, err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(b)
}

// meterClientCredentials performs the one legitimate exchange this client
// exists for: grant_type=client_credentials with its real secret.
func meterClientCredentials(t *testing.T, h *oauthMeterHarness, clientIP string) (int, string) {
	t.Helper()
	return meterPost(t, h, "/oauth/token", clientIP, url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {oauthMeterClientID},
		"client_secret": {oauthMeterSecret},
	})
}

// oauthMeterFloodSize is how many anonymous requests one address is allowed to
// send before the assertions bite. It is deliberately far above any plausible
// per-minute ceiling for these routes (the proposal is 120/min for the token
// endpoint and 300/min for introspection) and far below the "unbounded" the
// endpoints offer today.
const oauthMeterFloodSize = 400

// The token endpoint reaches a 64 MiB argon2id verification for every request
// an anonymous caller sends, with only a public client_id needed to get there.
//
// This is the test that pins the DoS half: it counts the client lookups that
// each gate one argon2 hash. A limiter that is registered INSIDE the chain
// rather than outermost — so the handler still runs and only its response is
// swapped for a 429 — passes a status-code assertion and fails this one.
func TestRateLimit_OAuthTokenClientSecretVerificationIsBounded(t *testing.T) {
	h := newOAuthMeterHarness(t)

	// Positive control first: the client's own machine-to-machine exchange
	// works, so everything below is about metering and not about a broken
	// token endpoint.
	if code, body := meterClientCredentials(t, h, "198.51.100.7"); code != http.StatusOK {
		t.Fatalf("legitimate client_credentials exchange failed before any flood: %d %s", code, body)
	}

	const flood = 200 // each unmetered request costs one 64 MiB argon2 hash
	before := h.repo.clientLookups.Load()
	blocked := 0
	for range flood {
		code, _ := meterPost(t, h, "/oauth/token", "203.0.113.7", url.Values{
			"grant_type":    {"client_credentials"},
			"client_id":     {oauthMeterClientID},
			"client_secret": {"not-the-secret"},
		})
		if code == http.StatusTooManyRequests {
			blocked++
		}
	}
	hashes := h.repo.clientLookups.Load() - before

	if hashes >= flood {
		t.Fatalf("all %d anonymous /oauth/token requests from one address reached the client lookup that gates argon2id "+
			"(lookups=%d): each one allocates 64 MiB for the duration of the hash, so nothing caps what an unauthenticated "+
			"caller can make this host allocate, and nothing caps client-secret guessing either", flood, hashes)
	}
	if blocked == 0 {
		t.Fatalf("none of the %d anonymous /oauth/token requests from one address was refused with 429", flood)
	}

	// Positive control after the flood: a DIFFERENT client IP — the honest
	// M2M fleet on another egress address — still gets its token, so the
	// meter buckets per client and did not take the endpoint down globally.
	code, body := meterClientCredentials(t, h, "198.51.100.9")
	if code != http.StatusOK {
		t.Fatalf("a different client IP was refused after the flood (%d %s): the limiter must not be one global bucket", code, body)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal([]byte(body), &tok); err != nil || tok.AccessToken == "" {
		t.Fatalf("legitimate exchange returned no access token: %s", body)
	}
}

// All four anonymous wire endpoints must be metered, not just the token
// endpoint. /introspect and /revoke reach the same argon2 verify through
// authenticateClient; /oauth/device/code takes no client authentication at all
// and writes a device-code row per request, so an unmetered caller fills the
// table for free.
//
// The floods here use an unregistered client_id so the cost per request is a
// repository miss rather than a hash — the point being measured is the
// presence of a ceiling, which the counting test above already ties to argon2.
func TestRateLimit_OAuthWireEndpointsAreMetered(t *testing.T) {
	h := newOAuthMeterHarness(t)

	cases := []struct {
		name     string
		path     string
		clientIP string
		form     url.Values
		// control is a legitimate request from a separate address that must
		// keep working after the flood.
		control func(t *testing.T, ip string) (int, string)
	}{
		{
			name:     "token",
			path:     "/oauth/token",
			clientIP: "203.0.113.21",
			form: url.Values{
				"grant_type":    {"client_credentials"},
				"client_id":     {"no-such-client"},
				"client_secret": {"x"},
			},
			control: func(t *testing.T, ip string) (int, string) {
				return meterClientCredentials(t, h, ip)
			},
		},
		{
			name:     "introspect",
			path:     "/oauth/introspect",
			clientIP: "203.0.113.22",
			form: url.Values{
				"token":         {"whatever"},
				"client_id":     {"no-such-client"},
				"client_secret": {"x"},
			},
			control: func(t *testing.T, ip string) (int, string) {
				return meterPost(t, h, "/oauth/introspect", ip, url.Values{
					"token":         {"whatever"},
					"client_id":     {oauthMeterClientID},
					"client_secret": {oauthMeterSecret},
				})
			},
		},
		{
			name:     "revoke",
			path:     "/oauth/revoke",
			clientIP: "203.0.113.23",
			form: url.Values{
				"token":         {"whatever"},
				"client_id":     {"no-such-client"},
				"client_secret": {"x"},
			},
			control: func(t *testing.T, ip string) (int, string) {
				return meterPost(t, h, "/oauth/revoke", ip, url.Values{
					"token":         {"whatever"},
					"client_id":     {oauthMeterClientID},
					"client_secret": {oauthMeterSecret},
				})
			},
		},
		{
			name:     "device-code",
			path:     "/oauth/device/code",
			clientIP: "203.0.113.24",
			form: url.Values{
				"client_id": {"no-such-client"},
			},
			control: func(t *testing.T, ip string) (int, string) {
				return meterPost(t, h, "/oauth/device/code", ip, url.Values{
					"client_id": {oauthMeterClientID},
				})
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			blocked := 0
			for range oauthMeterFloodSize {
				if code, _ := meterPost(t, h, tc.path, tc.clientIP, tc.form); code == http.StatusTooManyRequests {
					blocked++
				}
			}
			if blocked == 0 {
				t.Fatalf("%s: %d anonymous requests from one address, none refused — the route carries no limiter at all",
					tc.path, oauthMeterFloodSize)
			}

			// Positive control from a separate address: the endpoint still
			// serves its legitimate caller.
			if code, body := tc.control(t, "198.51.100.30"); code == http.StatusTooManyRequests {
				t.Fatalf("%s: the legitimate caller on another address was refused with 429: %s", tc.path, body)
			}
		})
	}
}

// The token endpoint and introspection are different budgets. A resource
// server introspects once per INBOUND request, so it must not be starved by
// whatever traffic the login flow puts through /oauth/token from the same
// address.
func TestRateLimit_OAuthIntrospectHasItsOwnBucket(t *testing.T) {
	h := newOAuthMeterHarness(t)
	const ip = "203.0.113.44"

	// Spend the token endpoint's budget from this address.
	exhausted := false
	for range oauthMeterFloodSize {
		code, _ := meterPost(t, h, "/oauth/token", ip, url.Values{
			"grant_type":    {"client_credentials"},
			"client_id":     {"no-such-client"},
			"client_secret": {"x"},
		})
		if code == http.StatusTooManyRequests {
			exhausted = true
			break
		}
	}
	if !exhausted {
		t.Fatalf("/oauth/token never refused a request from %s in %d attempts — it is unmetered", ip, oauthMeterFloodSize)
	}

	// Introspection from the SAME address must still answer: separate op,
	// separate bucket.
	code, body := meterPost(t, h, "/oauth/introspect", ip, url.Values{
		"token":         {"whatever"},
		"client_id":     {oauthMeterClientID},
		"client_secret": {oauthMeterSecret},
	})
	if code == http.StatusTooManyRequests {
		t.Fatalf("/oauth/introspect was refused after /oauth/token spent its budget from the same address: %s", body)
	}
}
