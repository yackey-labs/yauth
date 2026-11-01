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

// TestValidate_RejectsWildcardOriginWithCredentials. The middleware now
// refuses to honour the combination rather than "working around" the Fetch
// standard's ban on literal "*" with credentials — ignoring the wildcard
// entry would have broken existing deployments silently — but "*" +
// credentials is never a legitimate config on the declarative surface, so
// Validate rejects it outright and the operator gets pointed at the fix.
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

// TestSecurityWarnings_BootstrapAdminInlinePassword. The inline
// bootstrap_admin.password predates the "secrets never inline" schema
// invariant and stays permitted for air-gapped setups — but it must be said
// out loud, like cookie_secure=false: a config file is committed, imaged and
// pasted far more readily than an env var or secret file.
func TestSecurityWarnings_BootstrapAdminInlinePassword(t *testing.T) {
	c := baseValidConfig()
	c.Plugins.EmailPassword.BootstrapAdmin.Enabled = true
	c.Plugins.EmailPassword.BootstrapAdmin.Password = "inline-secret"

	found := false
	for _, w := range c.SecurityWarnings() {
		if strings.Contains(w, "bootstrap_admin.password") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no advisory for inline bootstrap_admin.password; got %v", c.SecurityWarnings())
	}

	// Env/file-sourced secrets (and no secret at all) stay quiet.
	c.Plugins.EmailPassword.BootstrapAdmin.Password = ""
	for _, w := range c.SecurityWarnings() {
		if strings.Contains(w, "bootstrap_admin.password") {
			t.Fatalf("advisory fires without an inline password: %q", w)
		}
	}
}
