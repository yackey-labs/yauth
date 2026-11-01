// require_key_permissions_test.go — Item-2 wiring: the flag must be
// flippable from config, the startup WARN must fire when it is off, and the
// per-key grandfathering WARN must fire (once) when an unscoped key is used.
//
// The 403-vs-allow decision itself is already pinned at HTTP level in
// key_permissions_test.go (TestScim_UnscopedKey_RefusedWhenRequireKeyPermissions
// / TestScim_UnscopedKey_IsGrandfatheredByDefault); these cases pin the
// visibility half and the authorize() decision function directly.
package scim

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/humaapi"
	"github.com/yackey-labs/yauth/plugin"
	"github.com/yackey-labs/yauth/repo"
	"github.com/yackey-labs/yauth/repo/memrepo"
)

// warnHost wraps the shared fakeHost but captures logs instead of writing to
// slog.Default, so tests can assert the WARNs this item requires.
type warnHost struct {
	plugin.PluginHost
	buf    *bytes.Buffer
	logger *slog.Logger
}

func newWarnHost(r repo.Repository) *warnHost {
	h := &warnHost{PluginHost: newFakeHost(r, ""), buf: &bytes.Buffer{}}
	h.logger = slog.New(slog.NewJSONHandler(h.buf, nil))
	return h
}

func (h *warnHost) Logger() *slog.Logger { return h.logger }

// TestScim_StartupWarnWhenRequireKeyPermissionsFalse pins the one line the
// plugin must log at Routes registration when the compatibility rule is live.
func TestScim_StartupWarnWhenRequireKeyPermissionsFalse(t *testing.T) {
	r := memrepo.New()
	wh := newWarnHost(r)
	mux := http.NewServeMux()
	New(Config{}).(*scimPlugin).Routes(wh, mux, humaapi.New(mux), "")

	logs := wh.buf.String()
	if !strings.Contains(logs, "RequireKeyPermissions=false") {
		t.Fatalf("startup WARN missing with flag off:\n%s", logs)
	}
	if !strings.Contains(logs, "plugins.scim.require_key_permissions") {
		t.Fatalf("startup WARN must name the config flag:\n%s", logs)
	}
}

// TestScim_NoStartupWarnWhenStrict is the mirror: a strict deployment must
// boot quiet (or operators learn to ignore the line everywhere).
func TestScim_NoStartupWarnWhenStrict(t *testing.T) {
	r := memrepo.New()
	wh := newWarnHost(r)
	mux := http.NewServeMux()
	New(Config{RequireKeyPermissions: true}).(*scimPlugin).Routes(wh, mux, humaapi.New(mux), "")

	if logs := wh.buf.String(); strings.Contains(logs, "RequireKeyPermissions=false") {
		t.Fatalf("strict deployment must not log the compatibility WARN:\n%s", logs)
	}
}

// TestScim_GrandfatheredKeyWarnsOnce proves the per-key WARN fires when an
// unscoped key is used under the default — and exactly once per key per
// process, so a polling connector doesn't bury the log.
func TestScim_GrandfatheredKeyWarnsOnce(t *testing.T) {
	r := memrepo.New()
	tnt := seedTenant(t, r, "warn")
	wh := newWarnHost(r)
	p := New(Config{}).(*scimPlugin)

	legacy := seedKey(t, r, tnt.orgID, tnt.adminID, 21, keySpec{})
	ctx := context.Background()

	for i := 0; i < 2; i++ {
		prin, scimErr := p.authenticate(ctx, wh, "Bearer "+legacy, tnt.orgID, scimWrite)
		if scimErr != nil {
			t.Fatalf("grandfathered key must still authenticate (call %d): %+v", i, scimErr.Body)
		}
		if prin == nil || prin.OrgID != tnt.orgID {
			t.Fatalf("call %d: no principal", i)
		}
	}

	if n := strings.Count(wh.buf.String(), "deprecated compatibility rule"); n != 1 {
		t.Fatalf("per-key WARN count = %d, want exactly 1 (once per key per process):\n%s", n, wh.buf.String())
	}
}

// TestScim_AuthorizeDecision covers the decision function directly: an
// unscoped key is refused under strict mode on BOTH read and write, and
// allowed under the default.
func TestScim_AuthorizeDecision(t *testing.T) {
	r := memrepo.New()
	tnt := seedTenant(t, r, "decide")
	host := newFakeHost(r, "")

	rec := &domain.APIKey{ID: "unscoped", OrganizationID: &tnt.orgID}

	strict := New(Config{RequireKeyPermissions: true}).(*scimPlugin)
	if got := strict.authorize(host, rec, tnt.orgID, scimWrite); got == nil {
		t.Fatalf("strict authorize(write, unscoped) = allow, want 403")
	}
	if got := strict.authorize(host, rec, tnt.orgID, scimRead); got == nil {
		t.Fatalf("strict authorize(read, unscoped) = allow, want 403")
	}

	def := New(Config{}).(*scimPlugin)
	if got := def.authorize(host, rec, tnt.orgID, scimWrite); got != nil {
		t.Fatalf("default authorize(write, unscoped) = 403, want grandfathered allow")
	}
}
