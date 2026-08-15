// from_config_plugin_coverage_test.go — every plugin in the tree must be
// reachable from a config file.
//
// yauth ships two ways to assemble a server: the Go builder API, and
// NewFromConfig over a yauth.yaml. The config file is the documented way, and
// it is what a deployment actually checks in. A plugin that exists only in the
// builder API is, from that deployment's point of view, a plugin that does not
// exist.
//
// Three separate plugins reached that state without anyone noticing, and each
// was found by accident rather than by looking:
//
//   - webhooks had no encryption_key_env, so its secrets were chained to the
//     bearer JWT secret and rotating that bricked them.
//   - ssosaml had no section at all, so SAML SSO could not be turned on — and
//     when /sso/saml/acs grew a refusal whose message names an escape hatch,
//     that hatch was unreachable from config.
//   - auditexport had no section at all, in a plugin whose usual reason to
//     exist is a compliance obligation held by exactly the deployments that run
//     from a checked-in file.
//
// Counting to nineteen by hand is how all three happened. This test does the
// counting: it lists plugins/* on disk and asserts each has a field on
// yauthcfg.PluginsConfig. Adding a plugin without a section now fails here,
// with the name of the plugin, in the pull request that adds it.
package yauth_test

import (
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/yackey-labs/yauth/yauthcfg"
)

// pluginDirExempt lists plugins/* directories that are deliberately not a
// `plugins.<name>` section, with the reason. An entry is a decision, not an
// oversight.
var pluginDirExempt = map[string]string{
	// Not a plugin: a package of mailer backends selected by mailer.driver,
	// which has its own top-level config block.
	"mailer": "mailer backends are chosen by the top-level mailer.driver, not a plugins.* section",
}

// dirToField maps a plugins/<dir> name to the PluginsConfig field name, for the
// cases where they are not simply case-insensitive equal.
var dirToField = map[string]string{
	"apikey":        "APIKey",
	"asymjwt":       "AsymJWT",
	"auditexport":   "AuditExport",
	"emailpassword": "EmailPassword",
	"lockout":       "AccountLock",
	"magiclink":     "MagicLink",
	"oauth2server":  "OAuth2Server",
	"scim":          "SCIM",
	"ssooidc":       "SSOOIDC",
	"ssosaml":       "SSOSAML",
	"mfa":           "MFA",
	"oidc":          "OIDC",
}

func TestEveryPluginHasADeclarativeSection(t *testing.T) {
	entries, err := os.ReadDir("plugins")
	if err != nil {
		t.Fatal(err)
	}

	cfgType := reflect.TypeOf(yauthcfg.PluginsConfig{})
	fields := make(map[string]bool, cfgType.NumField())
	for i := 0; i < cfgType.NumField(); i++ {
		fields[cfgType.Field(i).Name] = true
	}

	var missing []string
	seen := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := e.Name()
		if reason, ok := pluginDirExempt[dir]; ok {
			t.Logf("exempt: plugins/%s (%s)", dir, reason)
			continue
		}
		seen++

		want, ok := dirToField[dir]
		if !ok {
			// Default: the field name is the directory name, case-insensitively.
			for name := range fields {
				if strings.EqualFold(name, dir) {
					want = name
					break
				}
			}
		}
		if want == "" || !fields[want] {
			missing = append(missing, dir)
		}
	}

	if seen == 0 {
		t.Fatal("found no plugin directories — this test has stopped testing anything")
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Fatalf("%d plugin(s) have no yauthcfg.PluginsConfig section, so they cannot be enabled from a "+
			"yauth.yaml at all:\n  %s\n\nAdd a <Name>PluginConfig struct, a field on PluginsConfig, and a "+
			"construction block in from_config.go — or list the directory in pluginDirExempt with a reason.",
			len(missing), strings.Join(missing, "\n  "))
	}
}
