// Route-level OpenAPI spec-drift guard.
//
// This is the guard that makes it impossible to ship a route whose OpenAPI
// operation is missing (or vice-versa) — the failure mode that caused
// yauth-go's hand-written spec to silently lag its handlers (lifecycle /
// logout / #126 routes served but undocumented).
//
// # HOW IT WORKS
//
// Plugins register their handlers via mux.Handle / mux.HandleFunc inside
// Routes. yauth.Build passes a passive recordingRouter wrapper (see
// yauth.go) that captures every (method, path) before delegating to the
// real *http.ServeMux, exposed via YAuth.RegisteredRoutes(). This test
// builds a YAuth with the FULL plugin set (so the served route set matches
// the coverage of openapi.Build()), then compares:
//
//   - served routes      = the recorded (METHOD, path) set
//   - documented routes  = the (METHOD, path) set from openapi.Build().Paths
//
// and asserts SET EQUALITY in BOTH directions:
//
//   - every served route has an operation  -> catches served-but-undocumented
//     (the real bug: a handler ships, the spec never learns about it).
//   - every operation has a served route   -> catches documented-but-unserved
//     (path typos, ops left behind by a handler rename/removal).
//
// Unlike a hand-maintained []Route table (which would itself drift), this
// OBSERVES the real registrations. Field-level drift (request/response body
// shapes) is intentionally NOT checked here — it is covered by the
// cross-repo scripts/openapi-conformance.py gate which diffs against the
// Rust reference spec. This guard covers ROUTE-LEVEL drift, which that gate
// cannot see because it only compares two specs, never the live handlers.
package yauth_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2"

	yauth "github.com/yackey-labs/yauth-go"
	"github.com/yackey-labs/yauth-go/openapi"
	"github.com/yackey-labs/yauth-go/plugins/admin"
	"github.com/yackey-labs/yauth-go/plugins/apikey"
	"github.com/yackey-labs/yauth-go/plugins/asymjwt"
	"github.com/yackey-labs/yauth-go/plugins/auditexport"
	"github.com/yackey-labs/yauth-go/plugins/bearer"
	"github.com/yackey-labs/yauth-go/plugins/emailpassword"
	"github.com/yackey-labs/yauth-go/plugins/lockout"
	"github.com/yackey-labs/yauth-go/plugins/magiclink"
	"github.com/yackey-labs/yauth-go/plugins/mfa"
	"github.com/yackey-labs/yauth-go/plugins/oauth"
	"github.com/yackey-labs/yauth-go/plugins/oauth/providers"
	"github.com/yackey-labs/yauth-go/plugins/oauth2server"
	"github.com/yackey-labs/yauth-go/plugins/oidc"
	"github.com/yackey-labs/yauth-go/plugins/organizations"
	"github.com/yackey-labs/yauth-go/plugins/passkey"
	"github.com/yackey-labs/yauth-go/plugins/scim"
	"github.com/yackey-labs/yauth-go/plugins/ssooidc"
	"github.com/yackey-labs/yauth-go/plugins/ssosaml"
	"github.com/yackey-labs/yauth-go/plugins/status"
	"github.com/yackey-labs/yauth-go/plugins/webhooks"
	"github.com/yackey-labs/yauth-go/repo/gormrepo"
)

// route is the comparison key: an uppercase HTTP method + the path pattern.
type route struct {
	method string
	path   string
}

// driftAllowlist holds the ONLY *intentional* exceptions to set-equality:
// a served route that legitimately has no OpenAPI operation, or an operation
// intentionally not mounted. It is NOT a place to hide drift the guard
// exists to catch — prefer enabling plugin config (e.g. DCREnabled to serve
// /oauth/register) over allowlisting.
//
// It is currently EMPTY: every genuinely-intended route (including /config,
// the three /.well-known/* documents, and /oauth/register with DCR enabled
// in the guard's wiring below) has a matching operation. Keep it that way.
var driftAllowlist = map[route]string{
	// route{"GET", "/some/path"}: "why this is intentionally exempt",
}

// knownSpecDrift is a BASELINE of pre-existing route-level drift that this
// guard discovered the day it was introduced — handlers that ship but whose
// OpenAPI operation was never written (the exact bug class this guard
// exists to prevent), plus one documented-but-unserved path mismatch.
//
// This is DISTINCT from driftAllowlist: these are NOT intentional, they are
// a to-be-fixed quarantine so the guard can be merged GREEN against today's
// reality while still failing on any NEW drift. The fix is a follow-up spec
// PR that adds these operations (and corrects the SAML metadata path); as
// each is documented/served, delete it from this map. The guard is
// self-tightening — TestSpecDriftBaselineStillDrifts fails if a baselined
// entry stops drifting, forcing the entry to be removed rather than letting
// the quarantine rot and mask a fixed-then-reintroduced route.
//
// Categories (see commit message / PR for the recommended follow-up):
//   - organizations: groups CRUD + members, org API-keys CRUD/rotate/usage
//   - oauth2server: client ban/unban/rotate-public-key, client groups + roles
//   - oauth2server (OIDC end_session): GET/POST /oauth/end_session
//   - ssooidc: GET single connection, /sso login/callback, backchannel-logout
//   - ssosaml: org-scoped SAML connection CRUD + metadata.xml, GET /sso/saml/slo
//   - auditexport: org-scoped destinations, PUT /audit/destinations/{id}
//   - (documented-but-unserved) GET /sso/saml/metadata/{cid}: spec path is
//     wrong; the served route is .../sso/saml/connections/{cid}/metadata.xml
var knownSpecDrift = map[route]bool{
	// served-but-undocumented (handlers exist, no OpenAPI operation):
	{"GET", "/oauth/end_session"}:                                          true,
	{"POST", "/oauth/end_session"}:                                         true,
	{"POST", "/oauth2/clients/{id}/ban"}:                                   true,
	{"POST", "/oauth2/clients/{id}/unban"}:                                 true,
	{"POST", "/oauth2/clients/{id}/rotate-public-key"}:                     true,
	{"GET", "/oauth2/clients/{id}/groups"}:                                 true,
	{"POST", "/oauth2/clients/{id}/groups"}:                                true,
	{"DELETE", "/oauth2/clients/{id}/groups/{gid}"}:                        true,
	{"GET", "/oauth2/clients/{id}/roles"}:                                  true,
	{"POST", "/oauth2/clients/{id}/roles"}:                                 true,
	{"DELETE", "/oauth2/clients/{id}/roles/{aid}"}:                         true,
	{"GET", "/organizations/{id}/api-keys"}:                                true,
	{"POST", "/organizations/{id}/api-keys"}:                               true,
	{"DELETE", "/organizations/{id}/api-keys/{key_id}"}:                    true,
	{"POST", "/organizations/{id}/api-keys/{key_id}/rotate"}:               true,
	{"GET", "/organizations/{id}/api-keys/{key_id}/usage"}:                 true,
	{"GET", "/organizations/{id}/groups"}:                                  true,
	{"POST", "/organizations/{id}/groups"}:                                 true,
	{"GET", "/organizations/{id}/groups/{gid}"}:                            true,
	{"PATCH", "/organizations/{id}/groups/{gid}"}:                          true,
	{"DELETE", "/organizations/{id}/groups/{gid}"}:                         true,
	{"GET", "/organizations/{id}/groups/{gid}/members"}:                    true,
	{"POST", "/organizations/{id}/groups/{gid}/members"}:                   true,
	{"DELETE", "/organizations/{id}/groups/{gid}/members/{user_id}"}:       true,
	{"GET", "/organizations/{id}/sso/connections/{cid}"}:                   true,
	{"GET", "/organizations/{id}/sso/saml/connections"}:                    true,
	{"POST", "/organizations/{id}/sso/saml/connections"}:                   true,
	{"GET", "/organizations/{id}/sso/saml/connections/{cid}"}:              true,
	{"PATCH", "/organizations/{id}/sso/saml/connections/{cid}"}:            true,
	{"DELETE", "/organizations/{id}/sso/saml/connections/{cid}"}:           true,
	{"GET", "/organizations/{id}/sso/saml/connections/{cid}/metadata.xml"}: true,
	{"GET", "/sso/login"}:                                                  true,
	{"GET", "/sso/callback"}:                                               true,
	{"POST", "/sso/callback"}:                                              true,
	{"POST", "/sso/backchannel-logout"}:                                    true,
	{"GET", "/sso/saml/slo"}:                                               true,
	{"GET", "/organizations/{org_id}/audit/destinations"}:                  true,
	{"POST", "/organizations/{org_id}/audit/destinations"}:                 true,
	{"PATCH", "/organizations/{org_id}/audit/destinations/{id}"}:           true,
	{"PUT", "/organizations/{org_id}/audit/destinations/{id}"}:             true,
	{"DELETE", "/organizations/{org_id}/audit/destinations/{id}"}:          true,
	{"PUT", "/audit/destinations/{id}"}:                                    true,

	// documented-but-unserved (operation exists, no plugin serves it — the
	// spec path is wrong; corrected path is the metadata.xml route above):
	{"GET", "/sso/saml/metadata/{cid}"}: true,
}

// buildFullStack builds a YAuth with every plugin enabled, configured just
// enough that each plugin's New() succeeds and registers its full route set
// (notably oauth2server with DCR enabled so /oauth/register is served, to
// match the spec). The repo is an in-memory sqlite — no route registration
// depends on the data, only on construction succeeding.
func buildFullStack(t *testing.T) *yauth.YAuth {
	t.Helper()

	db, err := gormrepo.OpenSQLite("file::memory:?cache=shared&_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	// Migrate so background workers (e.g. webhooks claimer, which starts in
	// Routes regardless of WorkerCount) don't log missing-table warnings and
	// dirty the guard's output. Route registration itself touches no data.
	if err := gormrepo.Migrate(context.Background(), db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	repo := gormrepo.New(db)

	// A real RSA key so asymjwt.New (and thus the oidc id_token signer path)
	// constructs cleanly.
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	asym, err := asymjwt.New(asymjwt.Config{
		KeyType:       "RS256",
		PrivateKeyPEM: privPEM,
		PublicKeyPEM:  pubPEM,
		KID:           "drift-guard-key",
	})
	if err != nil {
		t.Fatalf("asymjwt.New: %v", err)
	}

	var encKey [32]byte
	for i := range encKey {
		encKey[i] = byte(i + 1)
	}

	mfaPlugin, err := mfa.New(mfa.Config{EncryptionKey: encKey, Issuer: "yauth"})
	if err != nil {
		t.Fatalf("mfa.New: %v", err)
	}

	oauthPlugin, err := oauth.New(oauth.Config{
		EncryptionKey: encKey,
		StateTTL:      5 * time.Minute,
		Providers: []oauth.Provider{
			providers.Google(providers.GoogleConfig{ClientID: "x", ClientSecret: "y", RedirectURL: "https://localhost/cb"}),
		},
	})
	if err != nil {
		t.Fatalf("oauth.New: %v", err)
	}

	passkeyPlugin, err := passkey.New(passkey.Config{
		RPID:      "localhost",
		RPName:    "yauth",
		RPOrigins: []string{"https://localhost"},
	})
	if err != nil {
		t.Fatalf("passkey.New: %v", err)
	}

	ssoOIDCPlugin, err := ssooidc.New(ssooidc.Config{
		EncryptionKey:       encKey,
		StateTTL:            5 * time.Minute,
		JWKSCacheTTL:        time.Minute,
		JWKSRefreshCooldown: time.Second,
	})
	if err != nil {
		t.Fatalf("ssooidc.New: %v", err)
	}

	ssoSAMLPlugin, err := ssosaml.New(ssosaml.Config{
		EncryptionKey:   encKey,
		AuthnRequestTTL: 5 * time.Minute,
		ReplayCacheTTL:  5 * time.Minute,
		ClockSkew:       time.Minute,
	})
	if err != nil {
		t.Fatalf("ssosaml.New: %v", err)
	}

	const apiKeyPrefix = "yauth_ak"

	ya, err := yauth.New(repo, yauth.NewDefaultConfig()).
		WithPlugin(emailpassword.New(emailpassword.Config{})).
		WithPlugin(bearer.New(bearer.Config{JWTSecret: []byte("test-secret-for-drift-guard-32by")})).
		WithPlugin(apikey.New(apikey.Config{Prefix: apiKeyPrefix})).
		WithPlugin(magiclink.New(magiclink.Config{})).
		WithPlugin(lockout.New(lockout.Config{})).
		WithPlugin(status.New()).
		WithPlugin(admin.New()).
		WithPlugin(mfaPlugin).
		WithPlugin(passkeyPlugin).
		WithPlugin(oauthPlugin).
		WithPlugin(webhooks.New(webhooks.Config{})).
		WithPlugin(asym).
		WithPlugin(oidc.New(oidc.Config{})).
		WithPlugin(oauth2server.New(oauth2server.Config{DCREnabled: true})).
		WithPlugin(organizations.New(organizations.Config{APIKeyPrefix: apiKeyPrefix})).
		WithPlugin(ssoOIDCPlugin).
		WithPlugin(ssoSAMLPlugin).
		WithPlugin(scim.New(scim.Config{APIKeyPrefix: apiKeyPrefix})).
		WithPlugin(auditexport.New(auditexport.Config{})).
		Build()
	if err != nil {
		t.Fatalf("build full stack: %v", err)
	}
	return ya
}

// servedRoutes returns the deduplicated (method, path) set the full plugin
// stack actually registered.
func servedRoutes(t *testing.T) map[route]bool {
	t.Helper()
	ya := buildFullStack(t)
	got := ya.RegisteredRoutes()
	// Sanity: a guard that passes because it recorded zero routes is the
	// classic false-green (recording wrapper not wired into Build).
	if len(got) < 150 {
		t.Fatalf("recorded only %d routes — recording wrapper not wired? expected ~190+", len(got))
	}
	set := make(map[route]bool, len(got))
	for _, r := range got {
		set[route{method: strings.ToUpper(r.Method), path: r.Path}] = true
	}
	return set
}

// documentedRoutes returns the (method, path) set declared in the spec.
// Plugins only register the five mutating/reading verbs; enumerate exactly
// those on the spec side so a verb present on one side but not the other is
// reported rather than silently dropped.
func documentedRoutes(t *testing.T) map[route]bool {
	t.Helper()
	api := openapi.Build()
	set := map[route]bool{}
	for path, item := range api.Paths {
		for method, op := range map[string]*huma.Operation{
			"GET":    item.Get,
			"POST":   item.Post,
			"PUT":    item.Put,
			"PATCH":  item.Patch,
			"DELETE": item.Delete,
		} {
			if op != nil {
				set[route{method: method, path: path}] = true
			}
		}
	}
	// Guard against a plugin (or future change) registering a verb the spec
	// side doesn't enumerate. huma.PathItem also exposes Head/Options/Trace;
	// none of the plugins register those, but if one starts, fail loudly so
	// the comparison stays exhaustive.
	for path, item := range api.Paths {
		for method, op := range map[string]*huma.Operation{
			"HEAD":    item.Head,
			"OPTIONS": item.Options,
			"TRACE":   item.Trace,
		} {
			if op != nil {
				t.Fatalf("spec declares an unmodeled verb %s %s — extend the guard's method set", method, path)
			}
		}
	}
	return set
}

// exempt reports whether route r is excused from a drift error: either an
// intentional allowlist entry or a baselined pre-existing drift.
func exempt(r route) bool {
	if _, ok := driftAllowlist[r]; ok {
		return true
	}
	return knownSpecDrift[r]
}

// TestSpecDriftGuard is the route-level both-direction guard. Set equality
// between the served route set and the documented route set, minus the
// (empty) intentional allowlist and the to-be-fixed knownSpecDrift baseline.
// Any NEW drift — a route served without an operation, or an operation with
// no served route — fails the build, naming the exact route.
func TestSpecDriftGuard(t *testing.T) {
	served := servedRoutes(t)
	documented := documentedRoutes(t)

	// Direction 1: served-but-undocumented (the real bug — a handler ships
	// with no OpenAPI operation).
	var undocumented []route
	for r := range served {
		if documented[r] || exempt(r) {
			continue
		}
		undocumented = append(undocumented, r)
	}

	// Direction 2: documented-but-unserved (path typos / ops left behind by
	// a handler rename or removal).
	var unserved []route
	for r := range documented {
		if served[r] || exempt(r) {
			continue
		}
		unserved = append(unserved, r)
	}

	if len(undocumented) > 0 {
		sortRoutes(undocumented)
		for _, r := range undocumented {
			t.Errorf("served-but-undocumented: %s %s is registered by a plugin but has no OpenAPI operation in openapi.Build() — add it to the spec (or, if pre-existing, to knownSpecDrift with a follow-up)", r.method, r.path)
		}
	}
	if len(unserved) > 0 {
		sortRoutes(unserved)
		for _, r := range unserved {
			t.Errorf("documented-but-unserved: %s %s has an OpenAPI operation but no plugin registers it — fix the spec path/method or wire the handler", r.method, r.path)
		}
	}
}

// TestSpecDriftBaselineStillDrifts keeps the knownSpecDrift quarantine
// honest and self-tightening: every baselined entry must STILL be drifting.
// If a route was documented (or its handler removed) so that it no longer
// drifts, this fails and demands the entry be deleted from knownSpecDrift —
// preventing the baseline from going stale and silently masking a
// fixed-then-reintroduced route. (driftAllowlist is intentional and exempt
// from this check.)
func TestSpecDriftBaselineStillDrifts(t *testing.T) {
	served := servedRoutes(t)
	documented := documentedRoutes(t)

	var resolved []route
	for r := range knownSpecDrift {
		servedR, docR := served[r], documented[r]
		// Still drifting iff exactly one side has it (served XOR documented).
		if servedR != docR {
			continue
		}
		resolved = append(resolved, r)
	}
	if len(resolved) > 0 {
		sortRoutes(resolved)
		for _, r := range resolved {
			t.Errorf("knownSpecDrift entry %s %s no longer drifts (served and documented now agree) — remove it from the baseline", r.method, r.path)
		}
	}
}

func sortRoutes(rs []route) {
	sort.Slice(rs, func(i, j int) bool {
		if rs[i].path != rs[j].path {
			return rs[i].path < rs[j].path
		}
		return rs[i].method < rs[j].method
	})
}
