// from_config_ssosaml_test.go — plugins/ssosaml had no declarative surface at
// all, so SAML SSO was unreachable from a yauth.yaml.
//
// Nineteen plugins ship in this tree. Seventeen have a `plugins.<name>` section
// in yauthcfg and a construction block in from_config.go. ssosaml was one of the
// two that did not (auditexport is the other), which means every deployment run
// the documented way — a config file — simply could not turn SAML SSO on, no
// matter what it wrote. The Go builder API could; the loader could not.
//
// That is a gap on its own, and it became a sharper one when /sso/saml/acs
// started refusing an SP-initiated response presented by a browser that did not
// start the flow. That refusal names an escape hatch for deployments which
// cannot carry the binding cookie across the ACS boundary — and the hatch sat
// behind a struct field a config-file deployment had no way to set. A guard
// whose documented opt-out is unreachable is a guard an operator cannot recover
// from.
//
// These cases pin the whole path: the section is accepted by the strict loader,
// enabling it actually registers the plugin's routes, the binding knob reaches
// the plugin, and an invalid value is refused loudly rather than silently
// defaulted.
package yauth_test

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	yauth "github.com/yackey-labs/yauth"
	"github.com/yackey-labs/yauth/repo/memrepo"
	"github.com/yackey-labs/yauth/yauthcfg"
)

func samlConfig(t *testing.T) *yauthcfg.Config {
	t.Helper()
	c := yauthcfg.Default()
	c.Database.Driver = "memory"
	c.Database.DSN = ""
	c.Plugins.EmailPassword.Enabled = true
	c.Plugins.APIKey.Enabled = true
	c.Plugins.Organizations.Enabled = true
	c.Plugins.SSOSAML.Enabled = true
	c.Plugins.SSOSAML.EncryptionKeyEnv = "YAUTH_TEST_SAML_KEY"
	return c
}

// TestSSOSAMLFromConfig_RegistersTheRoutes is the load-bearing case: enabling
// the section must actually mount the SAML flow. Before the section existed
// there was no way to express this at all.
func TestSSOSAMLFromConfig_RegistersTheRoutes(t *testing.T) {
	t.Setenv("YAUTH_TEST_SAML_KEY", "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")

	ya, err := yauth.NewFromConfig(context.Background(), samlConfig(t), yauth.WithRepo(memrepo.New()))
	if err != nil {
		t.Fatalf("NewFromConfig with plugins.sso_saml enabled: %v", err)
	}
	srv := httptest.NewServer(ya.Router())
	t.Cleanup(srv.Close)

	// A GET with no connection_id is a 4xx from the handler, which is proof the
	// route is mounted — a missing route is a 404 with huma's own body.
	resp, err := srv.Client().Get(srv.URL + "/sso/saml/login")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		t.Fatal("/sso/saml/login is not mounted: plugins.sso_saml.enabled did not register the plugin, " +
			"so SAML SSO cannot be turned on from a config file")
	}
}

// TestSSOSAMLFromConfig_LoginStateBindingReachable is the escape hatch. The
// binding refusal tells operators to set this; that instruction is only true if
// the value actually reaches the plugin from config.
func TestSSOSAMLFromConfig_LoginStateBindingReachable(t *testing.T) {
	t.Setenv("YAUTH_TEST_SAML_KEY", "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")

	for _, mode := range []string{"auto", "required", "off", ""} {
		c := samlConfig(t)
		c.Plugins.SSOSAML.LoginStateBinding = mode
		if _, err := yauth.NewFromConfig(context.Background(), c, yauth.WithRepo(memrepo.New())); err != nil {
			t.Fatalf("login_state_binding=%q rejected: %v", mode, err)
		}
	}
}

// TestSSOSAMLFromConfig_RefusesAnUnknownBindingMode is the other half. A
// mistyped "of" must not silently become "auto" and quietly re-open login CSRF
// on a Secure deployment — the operator has to be told.
func TestSSOSAMLFromConfig_RefusesAnUnknownBindingMode(t *testing.T) {
	t.Setenv("YAUTH_TEST_SAML_KEY", "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")

	c := samlConfig(t)
	c.Plugins.SSOSAML.LoginStateBinding = "of"
	_, err := yauth.NewFromConfig(context.Background(), c, yauth.WithRepo(memrepo.New()))
	if err == nil {
		t.Fatal("a mistyped login_state_binding was accepted; it would silently fall back to a mode the " +
			"operator did not choose")
	}
	if !strings.Contains(err.Error(), "login_state_binding") {
		t.Fatalf("the error must name the knob so it is fixable from the message; got: %v", err)
	}
}

// TestSSOSAMLFromConfig_RequiresAKey guards the at-rest key. Every plugin that
// seals data has an encryption_key_env and refuses to boot without it; this one
// must not be the exception that stores IdP secrets under a zero key.
func TestSSOSAMLFromConfig_RequiresAKey(t *testing.T) {
	c := samlConfig(t)
	c.Plugins.SSOSAML.EncryptionKeyEnv = "YAUTH_TEST_SAML_KEY_UNSET"
	if _, err := yauth.NewFromConfig(context.Background(), c, yauth.WithRepo(memrepo.New())); err == nil {
		t.Fatal("sso_saml booted with no encryption key: connection secrets would be sealed under a zero key")
	}
}
