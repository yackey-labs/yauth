// The yaml layer's half of the cross-site-write finding.
//
// What was broken: every cookie-authenticated write in the library authorized
// on the ambient session cookie alone, so a page a signed-in admin merely had
// open could POST /admin/users/{id}/suspend and the write landed. The guard
// that closes it lives in middleware/crosssite.go and the end-to-end proof is
// security_cross_site_write_test.go; this file guards the seam between the
// config FILE and that guard.
//
// Two things about the seam can go silently wrong:
//
//   - The keys must EXIST on yauthcfg.Server. Decoding is strict
//     (yauthcfg.Load sets KnownFields(true)), so an operator who follows the
//     escape hatch printed in the 403 body — the one instruction they have
//     when the guard refuses their SPA at 2am — gets a config that refuses to
//     load at all if the field is missing. That is the worst possible failure
//     for a knob whose entire purpose is to be reachable in a hurry.
//   - The polarity must NOT flip here. Unlike security_headers (tri-state
//     `enabled` in yaml, `Disabled` in Go), this switch is spelled `allow` on
//     both sides: false/omitted enforces the guard. One inverted assignment
//     would ship the guard dead for every yaml-configured deployment while
//     every router-level test stayed green, because those build their config
//     in Go.
package yauth

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/yackey-labs/yauth/yauthcfg"
)

func TestConfigToYAuthConfig_CrossSiteWrites(t *testing.T) {
	// POSITIVE CONTROL for the default: an operator who never heard of this
	// setting must get the guard ON and an empty list (which the builder then
	// fills from server.cors.allowed_origins).
	def := configToYAuthConfig(yauthcfg.Default())
	if def.CrossSiteWrites.Allow {
		t.Errorf("default config disables the cross-site guard; omitted must ENFORCE it")
	}
	if len(def.CrossSiteWrites.Origins) != 0 {
		t.Errorf("default Origins = %v, want empty so the builder inherits server.cors.allowed_origins",
			def.CrossSiteWrites.Origins)
	}

	c := yauthcfg.Default()
	c.Server.CrossSiteWrites.Allow = true
	c.Server.CrossSiteWrites.Origins = []string{"https://app.example.com"}
	out := configToYAuthConfig(c)
	if !out.CrossSiteWrites.Allow {
		t.Errorf("allow=true did not reach YAuthConfig — the guard would stay on and an operator's escape hatch would do nothing")
	}
	if len(out.CrossSiteWrites.Origins) != 1 || out.CrossSiteWrites.Origins[0] != "https://app.example.com" {
		t.Errorf("Origins = %v, want [https://app.example.com]", out.CrossSiteWrites.Origins)
	}
}

// TestLoadYAML_ServerCrossSiteWrites: the keys an operator is TOLD to write —
// middleware.CrossSiteWriteDetail names server.cross_site_writes.origins and
// server.cross_site_writes.allow verbatim — must actually parse under strict
// decoding.
func TestLoadYAML_ServerCrossSiteWrites(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "yauth.yaml")
	body := []byte(`database:
  driver: sqlite
  dsn: "file::memory:?cache=shared"
server:
  cross_site_writes:
    allow: false
    origins:
      - https://app.example.com
      - https://admin.example.com
`)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := yauthcfg.Load(path)
	if err != nil {
		t.Fatalf("Load: %v — the keys named in the 403 body do not parse", err)
	}
	if cfg.Server.CrossSiteWrites.Allow {
		t.Errorf("allow parsed as true from an explicit false")
	}
	if got := cfg.Server.CrossSiteWrites.Origins; len(got) != 2 || got[0] != "https://app.example.com" {
		t.Errorf("origins = %v, want the two listed origins", got)
	}
}
