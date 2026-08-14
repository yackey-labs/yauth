package ssooidc_test

// federate_redirect_test.go — the guided-handshake start route redirects the
// admin's browser to a URL it takes verbatim off the query string.
//
// registerFederateStart (federate_handshake.go) reads `idp` straight from
// r.URL.Query(), checks only that it is non-empty, signs a federation_request
// JWT with this deployment's own asymjwt key, and returns
//
//	Location: idpBase + "/federate/approve?req=" + url.QueryEscape(req)
//
// Nothing between the query parameter and the Location header looks at the
// scheme or the host. That is an open redirect on an authenticated admin
// route, and it does not merely bounce the browser: the signed
// federation_request goes with it. That token carries this app's
// redirect_uris, its initiate_login_uri and its return_uri, signed by the key
// the app publishes at its JWKS — everything an attacker needs to run the
// approval half of the handshake themselves and hand back a grant of their
// choosing to /sso/federate/return.
//
// A javascript: URL is the sharper end of the same hole: the handler will
// happily emit Location: javascript:alert(1)/federate/approve?req=..., which
// several user agents have historically executed on navigation.
//
// The positive control is the real handshake — an https IdP base must still
// 302 and must still carry the signed request — because a fix that rejected
// everything would silently disable guided federation, which is the feature
// this route exists for.

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestFederateStart_RejectsNonHTTPIdPBase(t *testing.T) {
	srv, _, adminKey, _ := rpWithSigner(t)

	// Each of these is a Location the browser must never be handed.
	for _, idp := range []string{
		"javascript:alert(1)",                      // executed on navigation by some agents
		"data:text/html,<script>alert(1)</script>", // same, as an inline document
		"//evil.example",                           // scheme-relative: resolves to https://evil.example
		"file:///etc/passwd",                       // not a network destination at all
		"http://",                                  // no host
	} {
		t.Run(idp, func(t *testing.T) {
			res := getWithKey(t, srv.URL+"/api/auth/sso/federate/start?idp="+url.QueryEscape(idp)+"&name=x", adminKey)
			defer res.Body.Close() //nolint:errcheck
			loc := res.Header.Get("Location")
			if res.StatusCode == http.StatusFound {
				t.Fatalf("302'd an admin (and the signed federation_request) to %q — Location: %s", idp, loc)
			}
			if res.StatusCode != http.StatusBadRequest {
				t.Fatalf("idp=%q: status=%d, want 400", idp, res.StatusCode)
			}
		})
	}
}

// Positive control: the handshake this route exists for still works, and the
// signed request still rides along.
func TestFederateStart_HTTPSIdPBaseStillRedirects(t *testing.T) {
	srv, _, adminKey, _ := rpWithSigner(t)

	res := getWithKey(t, srv.URL+"/api/auth/sso/federate/start?idp=https://idp.test.example&name=central", adminKey)
	defer res.Body.Close() //nolint:errcheck
	if res.StatusCode != http.StatusFound {
		t.Fatalf("legitimate https IdP base: status=%d, want 302", res.StatusCode)
	}
	loc := res.Header.Get("Location")
	if !strings.HasPrefix(loc, "https://idp.test.example/federate/approve?req=") {
		t.Fatalf("legitimate handshake lost its target: %s", loc)
	}
	if len(strings.Split(strings.SplitN(loc, "req=", 2)[1], ".")) != 3 {
		t.Fatalf("legitimate handshake lost its signed request: %s", loc)
	}
}
