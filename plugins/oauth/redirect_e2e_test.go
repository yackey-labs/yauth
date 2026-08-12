package oauth_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/yackey-labs/yauth/plugins/oauth"
)

// TestOAuthCallback_RefusesBrowserNormalisedOpenRedirect drives the real
// /authorize → provider → /callback flow and asserts on the STATE that
// matters: the Location header the browser is handed never resolves to a
// foreign origin.
//
// The pre-fix safeRedirect rejected only a literal "//" prefix. A browser
// applies the WHATWG URL rules BEFORE it navigates: tab/LF/CR are stripped
// from the URL, and in the "relative slash" state a backslash is treated as a
// forward slash. So "/\evil.com" — accepted by the old check as a host
// relative path — is parsed as "//evil.com" and navigates to
// https://evil.com/. The value survives byte-for-byte because it is emitted
// through huma's `header:"Location"` field rather than http.Redirect, so
// nothing normalises it on the way out.
//
// The assertion resolves the emitted Location against the server's own origin
// exactly as a browser would (after the same character stripping) and requires
// the result to stay on that origin.
func TestOAuthCallback_RefusesBrowserNormalisedOpenRedirect(t *testing.T) {
	hostile := []string{
		`/\evil.com`,
		`/\/evil.com`,
		"/\t/evil.com",
		"/\n/evil.com",
		"/\r/evil.com",
		`\\evil.com`,
		"//evil.com/path",
	}

	for i, target := range hostile {
		t.Run(url.QueryEscape(target), func(t *testing.T) {
			s := newStack(t, oauth.UserInfo{
				// A distinct remote id per case so each subtest provisions
				// its own user rather than racing on one.
				ProviderUserID: "redir-victim-" + string(rune('a'+i)),
				Email:          string(rune('a'+i)) + ".victim@example.com",
				EmailVerified:  true,
			})

			cbURL, _ := followAuthorizeAndExtractCallback(t, s, target)
			res, err := s.client.Get(cbURL)
			if err != nil {
				t.Fatalf("callback: %v", err)
			}
			defer res.Body.Close() //nolint:errcheck

			loc := res.Header.Get("Location")
			if loc == "" {
				// No redirect emitted at all is a perfectly good refusal.
				return
			}
			if !sameOriginAfterBrowserNormalisation(t, s.srv.URL, loc) {
				t.Fatalf("open redirect: redirect_url=%q produced Location=%q, which a browser resolves off-origin", target, loc)
			}
		})
	}
}

// sameOriginAfterBrowserNormalisation resolves loc against base the way a
// browser does — stripping the tab/LF/CR that the URL parser removes, and
// treating the backslashes in a leading slash run as forward slashes — and
// reports whether the result stays on base's origin.
func sameOriginAfterBrowserNormalisation(t *testing.T, base, loc string) bool {
	t.Helper()
	normalised := strings.NewReplacer("\t", "", "\n", "", "\r", "").Replace(loc)
	normalised = strings.ReplaceAll(normalised, `\`, "/")

	baseURL, err := url.Parse(base)
	if err != nil {
		t.Fatalf("parse base %q: %v", base, err)
	}
	ref, err := url.Parse(normalised)
	if err != nil {
		// Unparseable means the browser cannot navigate anywhere with it.
		return true
	}
	resolved := baseURL.ResolveReference(ref)
	return resolved.Scheme == baseURL.Scheme && resolved.Host == baseURL.Host
}

// TestOAuthCallback_HonoursLegitimateRedirects is the control: the fix must
// not have made the feature useless. A plain relative path and an
// allow-listed absolute URL both still come back in the Location header.
func TestOAuthCallback_HonoursLegitimateRedirects(t *testing.T) {
	t.Run("relative", func(t *testing.T) {
		s := newStack(t, oauth.UserInfo{
			ProviderUserID: "redir-ok-rel",
			Email:          "ok.rel@example.com",
			EmailVerified:  true,
		})
		cbURL, _ := followAuthorizeAndExtractCallback(t, s, "/dashboard?tab=1")
		res, err := s.client.Get(cbURL)
		if err != nil {
			t.Fatalf("callback: %v", err)
		}
		defer res.Body.Close() //nolint:errcheck
		if res.StatusCode != http.StatusFound {
			t.Fatalf("expected 302, got %d", res.StatusCode)
		}
		if got := res.Header.Get("Location"); got != "/dashboard?tab=1" {
			t.Fatalf("relative redirect dropped: Location=%q", got)
		}
	})

	t.Run("allow_listed_absolute", func(t *testing.T) {
		const allowed = "https://app.example.com"
		s := newStackWithRedirects(t, oauth.UserInfo{
			ProviderUserID: "redir-ok-abs",
			Email:          "ok.abs@example.com",
			EmailVerified:  true,
		}, []string{allowed})
		cbURL, _ := followAuthorizeAndExtractCallback(t, s, allowed+"/landing")
		res, err := s.client.Get(cbURL)
		if err != nil {
			t.Fatalf("callback: %v", err)
		}
		defer res.Body.Close() //nolint:errcheck
		if got := res.Header.Get("Location"); got != allowed+"/landing" {
			t.Fatalf("allow-listed redirect dropped: Location=%q", got)
		}
	})
}
