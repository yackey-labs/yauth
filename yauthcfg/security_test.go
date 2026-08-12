package yauthcfg

import (
	"strings"
	"testing"
)

// baseValidConfig is the smallest config Validate accepts, so each case below
// isolates the one setting it is about.
func baseValidConfig() Config {
	var c Config
	c.Database.Driver = "memory"
	return c
}

// TestValidate_RejectsSameSiteNoneWithoutSecure. Validate() accepted a cookie
// configuration no browser will store: Chrome 80+, Firefox 96+ and Safari 13+
// all REFUSE a SameSite=None cookie that is not Secure. The deployment's
// symptom is "logging in does nothing", with nothing in the logs to explain it.
func TestValidate_RejectsSameSiteNoneWithoutSecure(t *testing.T) {
	c := baseValidConfig()
	c.Session.CookieSameSite = "none"
	c.Session.CookieSecure = false

	err := c.Validate()
	if err == nil {
		t.Fatalf("SameSite=None with Secure=false was accepted")
	}
	if !strings.Contains(err.Error(), "cookie_secure") {
		t.Errorf("error does not name the field to fix: %v", err)
	}

	// The two legitimate neighbours must still pass.
	c.Session.CookieSecure = true
	if err := c.Validate(); err != nil {
		t.Errorf("SameSite=None with Secure=true rejected: %v", err)
	}
	c.Session.CookieSameSite = "lax"
	c.Session.CookieSecure = false
	if err := c.Validate(); err != nil {
		t.Errorf("SameSite=Lax with Secure=false rejected — that is the dev default: %v", err)
	}
}

// TestValidate_RejectsWildcardOriginWithCredentials. matchOrigin reflects the
// request's Origin when AllowedOrigins contains "*" AND AllowCredentials is
// set, which works around the Fetch standard's ban on literal "*" with
// credentials by removing the guard rather than the danger: every origin on the
// web can then make credentialed requests and READ the responses.
func TestValidate_RejectsWildcardOriginWithCredentials(t *testing.T) {
	c := baseValidConfig()
	c.Server.CORS.AllowedOrigins = []string{"*"}
	c.Server.CORS.AllowCredentials = true

	err := c.Validate()
	if err == nil {
		t.Fatalf(`allowed_origins ["*"] with allow_credentials=true was accepted`)
	}
	if !strings.Contains(err.Error(), "allow_credentials") {
		t.Errorf("error does not name the combination: %v", err)
	}

	// "*" WITHOUT credentials is a normal public-API config and stays legal.
	c.Server.CORS.AllowCredentials = false
	if err := c.Validate(); err != nil {
		t.Errorf(`allowed_origins ["*"] without credentials rejected: %v`, err)
	}

	// Named origins WITH credentials is the correct way to do this.
	c.Server.CORS.AllowedOrigins = []string{"https://app.example.com"}
	c.Server.CORS.AllowCredentials = true
	if err := c.Validate(); err != nil {
		t.Errorf("named origins with credentials rejected: %v", err)
	}
}

// TestSecurityWarnings_CookieSecureFalse. CookieSecure defaults to false and
// nothing anywhere said so — the whole point of the finding. It stays
// permitted (yauth cannot see whether a proxy terminates TLS) but is now said
// out loud, the way the console mailer announces itself.
func TestSecurityWarnings_CookieSecureFalse(t *testing.T) {
	c := baseValidConfig()
	c.Session.CookieSecure = false

	warns := c.SecurityWarnings()
	found := false
	for _, w := range warns {
		if strings.Contains(w, "cookie_secure") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no advisory for cookie_secure=false; got %v", warns)
	}

	c.Session.CookieSecure = true
	for _, w := range c.SecurityWarnings() {
		if strings.Contains(w, "cookie_secure") {
			t.Fatalf("advisory still fires with cookie_secure=true: %q", w)
		}
	}
}
