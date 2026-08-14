// Regression suite for "any web page can drive a yauth session cookie".
//
// Every cookie-authenticated route in this repo authorizes on the AMBIENT
// credential alone. middleware.ResolveAuth (middleware/middleware.go:349)
// reads the session cookie off the request, requireAuthHuma
// (middleware/huma.go:98) and RequireAdminHuma (middleware/huma.go:205) check
// role and must_change_password, and then the handler runs. Nothing anywhere
// on that path asks WHERE the request came from, so a browser sitting on an
// attacker's page that issues a state-changing POST at the yauth origin has
// the victim's cookie attached for it by the browser and the write lands.
//
// Two properties make this reachable without a CORS preflight, i.e. with no
// cooperation from yauth at all:
//
//   - Bodyless admin levers. POST /admin/users/{id}/suspend takes a POINTER
//     body (plugins/admin/handlers.go suspendInput), and the handler is
//     explicitly "lenient: an absent body is fine". /unban, /unsuspend and
//     /impersonate take a bare *idInput. A plain auto-submitting
//     <form method=POST> — a simple request, never preflighted — reaches all
//     of them.
//
//   - The huma JSON fallback. humaapi/humaapi.go sets Formats to
//     huma.DefaultFormats, and huma falls back to application/json when a
//     request carries NO Content-Type header at all. A cross-site
//     fetch() with `new Blob(body, {type: ""})` omits Content-Type, stays a
//     simple request, and huma parses the body as JSON regardless — so the
//     routes that DO need a body (ban, role changes, membership writes) are
//     equally reachable.
//
// SameSite is a PARTIAL mitigation, and it is worth being exact about which
// part. Lax — the default here (config.go NewDefaultConfig) — DOES withhold
// the cookie from a cross-site POST, which is why the two refusal cases below
// run the fixture with cookie_same_site=none, the deployment where a browser
// really does attach the cookie to the request they build. Two populations are
// exposed:
//
//   - cookie_same_site: none. A supported, documented setting (yauthcfg gates
//     it only on cookie_secure) and precisely the cross-domain-SPA shape this
//     library targets. The whole web can then drive the session. THIS is what
//     the guard closes.
//   - Script on any origin that is cross-ORIGIN but SAME-SITE — a marketing
//     subdomain, a customer-hosted page on *.example.com, an XSS in a sibling
//     app. Lax sends the cookie there, and the guard deliberately does NOT
//     close it either (Sec-Fetch-Site: same-site passes; see
//     TestCrossSiteWrite_SameSiteAllowed and middleware/crosssite.go).
//
// The refusals below are each paired with a POSITIVE CONTROL, because the
// cheap wrong fix — "refuse any request carrying an Origin header" — would
// blanket-block a same-origin SPA, a console on a sibling subdomain, every
// curl/CI caller that sends no browser headers at all, and the machine
// credentials (X-Api-Key / bearer) that a CSRF can never attach in the first
// place. Reads must stay untouched, and so must the unauthenticated routes
// that are cross-site BY DESIGN.
//
// Shared harness helpers (secHarness, secRegister, secPostJSON, ...) live in
// security_refresh_issuer_test.go.
package yauth_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	yauth "github.com/yackey-labs/yauth"
	"github.com/yackey-labs/yauth/auth"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/middleware"
	"github.com/yackey-labs/yauth/plugin"
	"github.com/yackey-labs/yauth/plugins/admin"
	"github.com/yackey-labs/yauth/plugins/apikey"
	"github.com/yackey-labs/yauth/plugins/emailpassword"
	"github.com/yackey-labs/yauth/plugins/oauth2server"
	"github.com/yackey-labs/yauth/repo/memrepo"
)

// newCrossSiteHarness boots emailpassword + admin + apikey against a
// caller-tweakable YAuthConfig, plus any extra plugins a case needs. It cannot
// reuse newSecHarness unmodified because several cases turn on config the
// shared helper does not expose: the allow-list case needs CORS.AllowedOrigins
// populated (the list the guard is specified to inherit), the
// machine-credential case needs AllowAdminMachineCallers, and the refusal
// cases need cookie_same_site=none. Same shape as newMachineCredHarness in
// security_machine_credential_test.go.
func newCrossSiteHarness(t *testing.T, tweak func(*yauth.YAuthConfig), extra ...plugin.Plugin) *secHarness {
	t.Helper()

	r := memrepo.New()
	cfg := yauth.NewDefaultConfig()
	cfg.RateLimit = yauth.RateLimitConfig{}
	if tweak != nil {
		tweak(&cfg)
	}

	b := yauth.New(r, cfg).
		WithJWTSecret([]byte(secJWTSecret)).
		WithPlugin(emailpassword.New(emailpassword.Config{
			MinPasswordLength: 12,
			HIBPCheck:         false,
			HIBPCheckSet:      true,
			Mailer:            secNullMailer{},
		})).
		WithPlugin(apikey.New(apikey.Config{})).
		WithPlugin(admin.New())
	for _, p := range extra {
		b = b.WithPlugin(p)
	}
	ya, err := b.Build()
	if err != nil {
		t.Fatalf("build yauth: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &secHarness{srv: srv, repo: r}
}

// xsFixture is one global admin (with a live cookie session and a personal
// user-scoped API key) plus one victim (with a live session of their own, so
// a case can assert that a refused suspend did NOT kill it).
type xsFixture struct {
	h            *secHarness
	adminID      string
	victimID     string
	adminCookie  *http.Cookie
	victimCookie *http.Cookie
	adminKey     string
}

// xsSameSiteNone is the deployment the two refusal cases model: a cookie the
// browser really does attach to a cross-site POST. Under the default
// SameSite=Lax the browser would withhold it, so without this the fixture
// would be describing a request no browser makes. cookie_same_site=none is
// supported and documented (yauthcfg gates it only on cookie_secure) and is
// exactly the cross-domain-SPA shape this library targets.
//
// Setting it is safe for the fixture: the cookie attributes only affect the
// Set-Cookie header yauth EMITS, and these cases hand-build their request
// cookies — the /login control below still sees its own cookie set.
func xsSameSiteNone(cfg *yauth.YAuthConfig) {
	cfg.CookieSameSite = "None"
	cfg.CookieSecure = true
}

func newXSFixture(t *testing.T, tweak func(*yauth.YAuthConfig), extra ...plugin.Plugin) *xsFixture {
	t.Helper()
	h := newCrossSiteHarness(t, tweak, extra...)
	ctx := context.Background()
	now := time.Now().UTC()

	adminID := secRegister(t, h, "root@example.test")
	victimID := secRegister(t, h, "victim@example.test")

	adminRole := "admin"
	if _, err := h.repo.UpdateUser(ctx, adminID, domain.UpdateUser{
		Role: &adminRole, UpdatedAt: &now,
	}); err != nil {
		t.Fatalf("promote admin: %v", err)
	}

	adminRaw, _, err := auth.IssueSession(ctx, h.repo, adminID, nil, nil, time.Hour)
	if err != nil {
		t.Fatalf("issue admin session: %v", err)
	}
	victimRaw, _, err := auth.IssueSession(ctx, h.repo, victimID, nil, nil, time.Hour)
	if err != nil {
		t.Fatalf("issue victim session: %v", err)
	}

	gen, err := apikey.GenerateKey("yak")
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	uid := adminID
	if err := h.repo.CreateAPIKey(ctx, domain.NewAPIKey{
		ID: "k-root-cli", UserID: &uid, KeyPrefix: gen.Prefix, KeyHash: gen.Hash,
		Name: "root-cli", Scopes: json.RawMessage(`[]`),
		CreatedAt: now, CreatedByUserID: adminID,
	}); err != nil {
		t.Fatalf("create user api key: %v", err)
	}

	return &xsFixture{
		h:            h,
		adminID:      adminID,
		victimID:     victimID,
		adminCookie:  &http.Cookie{Name: "yauth_session", Value: adminRaw},
		victimCookie: &http.Cookie{Name: "yauth_session", Value: victimRaw},
		adminKey:     gen.Plaintext,
	}
}

// xsReq is a hand-built request: the point of these cases is the exact header
// set a browser would emit on a cross-site write, so nothing here may be
// defaulted for us. body is sent verbatim; ctype empty means the
// Content-Type header is OMITTED entirely (the no-preflight trick).
type xsReq struct {
	method  string
	path    string
	body    string
	ctype   string
	cookie  *http.Cookie
	apiKey  string
	headers map[string]string
}

func (f *xsFixture) do(t *testing.T, rq xsReq) (int, string) {
	t.Helper()
	var rdr io.Reader
	if rq.body != "" {
		rdr = strings.NewReader(rq.body)
	}
	req, err := http.NewRequest(rq.method, f.h.url(rq.path), rdr)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	if rq.ctype != "" {
		req.Header.Set("Content-Type", rq.ctype)
	}
	if rq.cookie != nil {
		req.AddCookie(rq.cookie)
	}
	if rq.apiKey != "" {
		req.Header.Set("X-Api-Key", rq.apiKey)
	}
	for k, v := range rq.headers {
		req.Header.Set(k, v)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", rq.method, rq.path, err)
	}
	defer func() { _ = res.Body.Close() }()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(b)
}

// crossSiteHeaders is what Chrome/Firefox/Safari attach to a state-changing
// request issued by script on https://evil.example against this server.
var crossSiteHeaders = map[string]string{
	"Origin":         "https://evil.example",
	"Sec-Fetch-Site": "cross-site",
	"Sec-Fetch-Mode": "no-cors",
	"Sec-Fetch-Dest": "empty",
}

func (f *xsFixture) victim(t *testing.T) *domain.User {
	t.Helper()
	u, err := f.h.repo.GetUserByID(context.Background(), f.victimID)
	if err != nil {
		t.Fatalf("reload victim: %v", err)
	}
	return u
}

// victimSessionLive reports whether the victim's own session still resolves —
// suspend kills every session, so this is how a refused suspend is told apart
// from one that half-executed.
func (f *xsFixture) victimSessionLive(t *testing.T) bool {
	t.Helper()
	code, _ := f.do(t, xsReq{method: http.MethodGet, path: "/session", cookie: f.victimCookie})
	return code == http.StatusOK
}

// ---------------------------------------------------------------------------
// 1. The bodyless lever: a plain cross-site form POST suspends a user
// ---------------------------------------------------------------------------

// TestCrossSiteWrite_AdminSuspendRefused is the exploit in its cheapest form.
// No Content-Type, no body, no preflight, nothing the attacker needs beyond an
// <form action=".../suspend" method="post"> that submits itself while a
// signed-in admin has the page open. Suspend is the sharpest of the bodyless
// levers: it disables the account AND terminates every one of its sessions.
func TestCrossSiteWrite_AdminSuspendRefused(t *testing.T) {
	f := newXSFixture(t, xsSameSiteNone)

	code, body := f.do(t, xsReq{
		method:  http.MethodPost,
		path:    "/admin/users/" + f.victimID + "/suspend",
		cookie:  f.adminCookie,
		headers: crossSiteHeaders,
	})

	if got := f.victim(t); got.SuspendedAt != nil {
		t.Errorf("a cross-site POST (Origin: https://evil.example, Sec-Fetch-Site: cross-site) "+
			"carrying only the admin's ambient session cookie SUSPENDED the victim: "+
			"suspended_at=%v. Any page the admin visits can offboard any user.",
			got.SuspendedAt)
	}
	if !f.victimSessionLive(t) {
		t.Errorf("the cross-site suspend also terminated the victim's live session — " +
			"the write was not merely attempted, it completed")
	}
	if code != http.StatusForbidden {
		t.Errorf("cross-site cookie write returned %d, want 403; body=%s", code, body)
	}
	// The 403 has to teach an operator both escape hatches without the source;
	// this is the highest-blast-radius refusal in the release.
	for _, want := range []string{"cross_site_writes.origins", "cross_site_writes.allow"} {
		if !strings.Contains(body, want) {
			t.Errorf("refusal body does not name %q, so an operator reading a support ticket "+
				"cannot find the escape hatch; body=%s", want, body)
		}
	}
}

// ---------------------------------------------------------------------------
// 2. The bodied lever: omitting Content-Type keeps the request simple
// ---------------------------------------------------------------------------

// TestCrossSiteWrite_NoContentTypeBodyRefused covers the routes that need a
// JSON body. A cross-site fetch() with a `new Blob(..., {type: ""})` body sends
// NO Content-Type, so it is still a simple request (no preflight), and huma's
// DefaultFormats fall back to application/json anyway. Ban therefore has the
// same exposure as suspend. This case also pins that huma fallback: if a huma
// bump ever stops parsing an untyped body as JSON, this test says so out loud
// rather than silently becoming a no-op.
func TestCrossSiteWrite_NoContentTypeBodyRefused(t *testing.T) {
	f := newXSFixture(t, xsSameSiteNone)

	code, body := f.do(t, xsReq{
		method:  http.MethodPost,
		path:    "/admin/users/" + f.victimID + "/ban",
		body:    `{"reason":"pwned"}`,
		ctype:   "", // deliberately omitted: this is what keeps it preflight-free
		cookie:  f.adminCookie,
		headers: crossSiteHeaders,
	})

	if code == http.StatusBadRequest || code == http.StatusUnsupportedMediaType || code == http.StatusUnprocessableEntity {
		t.Fatalf("PREMISE CHANGED: the untyped body was not parsed as JSON (%d %s). "+
			"huma no longer falls back to application/json when Content-Type is absent, "+
			"which narrows this exploit — re-verify before deleting the case.", code, body)
	}
	if got := f.victim(t); got.Banned {
		var reason string
		if got.BannedReason != nil {
			reason = *got.BannedReason
		}
		t.Errorf("a cross-site POST with an untyped (preflight-free) JSON body BANNED the victim: "+
			"banned=%v reason=%q", got.Banned, reason)
	}
	if code != http.StatusForbidden {
		t.Errorf("cross-site cookie write returned %d, want 403; body=%s", code, body)
	}
}

// ---------------------------------------------------------------------------
// POSITIVE CONTROLS — every legitimate caller must still write
// ---------------------------------------------------------------------------

// TestCrossSiteWrite_SameOriginAllowed is the first-party SPA: same document
// origin as the API, Origin echoing the server's own host. The obvious wrong
// fix ("no Origin header, no write") blocks exactly this caller.
func TestCrossSiteWrite_SameOriginAllowed(t *testing.T) {
	f := newXSFixture(t, nil)

	code, body := f.do(t, xsReq{
		method: http.MethodPost,
		path:   "/admin/users/" + f.victimID + "/suspend",
		cookie: f.adminCookie,
		headers: map[string]string{
			"Origin":         f.h.srv.URL,
			"Sec-Fetch-Site": "same-origin",
			"Sec-Fetch-Mode": "cors",
		},
	})
	if code != http.StatusOK {
		t.Fatalf("same-origin admin write refused: %d %s", code, body)
	}
	if f.victim(t).SuspendedAt == nil {
		t.Fatalf("same-origin admin write returned 200 but did not suspend the user")
	}
}

// TestCrossSiteWrite_SameSiteAllowed is the console on a sibling subdomain
// (console.example.com -> auth.example.com), which is the overwhelmingly
// common deployment. Sec-Fetch-Site: same-site must keep writing. This is a
// documented LIMIT of the guard, not an oversight: script on any same-site
// origin still passes, and pinning it here stops it being tightened by
// accident and breaking every console.
func TestCrossSiteWrite_SameSiteAllowed(t *testing.T) {
	f := newXSFixture(t, nil)

	code, body := f.do(t, xsReq{
		method: http.MethodPost,
		path:   "/admin/users/" + f.victimID + "/suspend",
		cookie: f.adminCookie,
		headers: map[string]string{
			"Origin":         "https://console.example.com",
			"Sec-Fetch-Site": "same-site",
			"Sec-Fetch-Mode": "cors",
		},
	})
	if code != http.StatusOK {
		t.Fatalf("same-site (sibling subdomain console) admin write refused: %d %s", code, body)
	}
	if f.victim(t).SuspendedAt == nil {
		t.Fatalf("same-site admin write returned 200 but did not suspend the user")
	}
}

// TestCrossSiteWrite_NoBrowserHeadersAllowed is curl, k6, an embedder's Go
// integration suite, and SSR forwarding a cookie: neither Sec-Fetch-Site nor
// Origin. No browser omits both on a cross-site write, so failing these closed
// breaks every embedder's CI for no attacker gain.
func TestCrossSiteWrite_NoBrowserHeadersAllowed(t *testing.T) {
	f := newXSFixture(t, nil)

	code, body := f.do(t, xsReq{
		method: http.MethodPost,
		path:   "/admin/users/" + f.victimID + "/suspend",
		cookie: f.adminCookie,
	})
	if code != http.StatusOK {
		t.Fatalf("headerless (curl / CI) admin write refused: %d %s", code, body)
	}
	if f.victim(t).SuspendedAt == nil {
		t.Fatalf("headerless admin write returned 200 but did not suspend the user")
	}
}

// TestCrossSiteWrite_AllowListedOriginAllowed is the cross-domain SPA that
// already declares itself in server.cors.allowed_origins — it must, because a
// credentialed XHR cannot read its response otherwise. That inherited list is
// what carries this population across the change with ZERO new config, so the
// case asserts a cross-site request from a CORS-listed origin still writes.
func TestCrossSiteWrite_AllowListedOriginAllowed(t *testing.T) {
	f := newXSFixture(t, func(cfg *yauth.YAuthConfig) {
		cfg.CORS = yauth.CORSConfig{
			AllowedOrigins:   []string{"https://app.example.com"},
			AllowCredentials: true,
		}
	})

	code, body := f.do(t, xsReq{
		method: http.MethodPost,
		path:   "/admin/users/" + f.victimID + "/suspend",
		cookie: f.adminCookie,
		headers: map[string]string{
			"Origin":         "https://app.example.com",
			"Sec-Fetch-Site": "cross-site",
			"Sec-Fetch-Mode": "cors",
		},
	})
	if code != http.StatusOK {
		t.Fatalf("cross-domain SPA listed in server.cors.allowed_origins was refused: %d %s", code, body)
	}
	if f.victim(t).SuspendedAt == nil {
		t.Fatalf("allow-listed cross-site write returned 200 but did not suspend the user")
	}
}

// TestCrossSiteWrite_MachineCredentialUnaffected: a CSRF cannot make a browser
// attach an X-Api-Key (it is not ambient, and setting the header forces a
// preflight the guard-free server would refuse). A machine credential must
// therefore be exempt by construction, cross-site headers or not — otherwise
// automation calling from a build runner that happens to set Origin breaks.
func TestCrossSiteWrite_MachineCredentialUnaffected(t *testing.T) {
	f := newXSFixture(t, func(cfg *yauth.YAuthConfig) {
		cfg.AllowAdminMachineCallers = true
	})

	code, body := f.do(t, xsReq{
		method:  http.MethodPost,
		path:    "/admin/users/" + f.victimID + "/suspend",
		apiKey:  f.adminKey, // user-scoped key owned by the admin, no cookie
		headers: crossSiteHeaders,
	})
	if code != http.StatusOK {
		t.Fatalf("user-scoped X-Api-Key admin write refused with browser cross-site headers: %d %s",
			code, body)
	}
	if f.victim(t).SuspendedAt == nil {
		t.Fatalf("X-Api-Key admin write returned 200 but did not suspend the user")
	}
}

// TestCrossSiteWrite_ReadsUnaffected: the guard is about STATE CHANGES. A
// cross-site GET cannot be read by the attacker anyway (CORS blocks the
// response), and blocking reads would break every embedded dashboard.
func TestCrossSiteWrite_ReadsUnaffected(t *testing.T) {
	f := newXSFixture(t, nil)

	code, body := f.do(t, xsReq{
		method:  http.MethodGet,
		path:    "/admin/users",
		cookie:  f.adminCookie,
		headers: crossSiteHeaders,
	})
	if code != http.StatusOK {
		t.Fatalf("cross-site GET /admin/users refused: %d %s", code, body)
	}
}

// TestCrossSiteWrite_UnauthenticatedRouteUnaffected: routes that carry NO
// ambient authority are cross-site by design — a federated callback, a token
// exchange, a login form posted from a hosted page. The guard hangs off the
// authenticated chokepoints only, and login must keep working (and keep
// setting its cookie) when a browser labels it cross-site.
func TestCrossSiteWrite_UnauthenticatedRouteUnaffected(t *testing.T) {
	f := newXSFixture(t, nil)

	req, err := http.NewRequest(http.MethodPost, f.h.url("/login"),
		strings.NewReader(`{"email":"victim@example.test","password":"`+secPassword+`"}`))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range crossSiteHeaders {
		req.Header.Set(k, v)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post /login: %v", err)
	}
	defer func() { _ = res.Body.Close() }()
	b, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("cross-site POST /login refused: %d %s", res.StatusCode, b)
	}
	var sawCookie bool
	for _, c := range res.Cookies() {
		if c.Name == "yauth_session" && c.Value != "" {
			sawCookie = true
		}
	}
	if !sawCookie {
		t.Fatalf("cross-site POST /login returned 200 but set no session cookie: %s", b)
	}
}

// ---------------------------------------------------------------------------
// 3. The wildcard trap: a "*" inherited from CORS is NOT consent
// ---------------------------------------------------------------------------

// TestCrossSiteWrite_WildcardCORSDoesNotBypass pins the one place the guard
// must NOT simply reuse middleware/cors.go's matchOrigin, which returns true
// for a literal "*" unconditionally.
//
// yauthcfg already REFUSES `allowed_origins: ["*"]` together with
// `allow_credentials: true` (that combination lets any site READ authenticated
// responses). So the only way a "*" reaches this guard by inheritance is with
// allow_credentials=FALSE — an operator who explicitly DECLINED credentialed
// cross-origin access. Treating that as permission for cross-site credentialed
// WRITES would invert their stated intent, and allow_credentials=false is no
// protection here at all: a CSRF write never needs to read the response.
//
// The positive control is the same "*" aimed at THIS guard on purpose, via
// server.cross_site_writes.origins, which must still work — otherwise the
// escape hatch named in the 403 body would be a lie.
func TestCrossSiteWrite_WildcardCORSDoesNotBypass(t *testing.T) {
	inherited := newXSFixture(t, func(cfg *yauth.YAuthConfig) {
		xsSameSiteNone(cfg)
		cfg.CORS = yauth.CORSConfig{
			AllowedOrigins:   []string{"*"},
			AllowCredentials: false, // the only shape yauthcfg lets "*" have
		}
	})

	code, body := inherited.do(t, xsReq{
		method:  http.MethodPost,
		path:    "/admin/users/" + inherited.victimID + "/suspend",
		cookie:  inherited.adminCookie,
		headers: crossSiteHeaders,
	})
	if got := inherited.victim(t); got.SuspendedAt != nil {
		t.Errorf(`a "*" inherited from server.cors.allowed_origins (with allow_credentials=false, `+
			`the ONLY shape yauthcfg permits) let a cross-site page suspend a user: suspended_at=%v`,
			got.SuspendedAt)
	}
	if code != http.StatusForbidden {
		t.Errorf("cross-site write under an inherited CORS wildcard returned %d, want 403; body=%s", code, body)
	}

	// POSITIVE CONTROL: "*" set on the guard's OWN knob is a deliberate
	// operator decision and must still let the write through.
	explicit := newXSFixture(t, func(cfg *yauth.YAuthConfig) {
		xsSameSiteNone(cfg)
		cfg.CrossSiteWrites = yauth.CrossSiteWriteConfig{Origins: []string{"*"}}
	})
	code, body = explicit.do(t, xsReq{
		method:  http.MethodPost,
		path:    "/admin/users/" + explicit.victimID + "/suspend",
		cookie:  explicit.adminCookie,
		headers: crossSiteHeaders,
	})
	if code != http.StatusOK {
		t.Fatalf(`server.cross_site_writes.origins: ["*"] refused the write anyway: %d %s`, code, body)
	}
	if explicit.victim(t).SuspendedAt == nil {
		t.Fatalf(`server.cross_site_writes.origins: ["*"] returned 200 but did not suspend the user`)
	}
}

// ---------------------------------------------------------------------------
// 4. The chokepoint the four middleware gates miss
// ---------------------------------------------------------------------------

// TestCrossSiteWrite_DCRRegisterRefused covers POST /oauth/register, which is
// NOT reached by wiring the guard into RequireAuth / RequireAdmin and their
// huma twins. That route is registered with the `public` chain (stash only, no
// RequireAdmin wrapper) because it applies its own split policy — anonymous
// self-registration for a loopback-only public client, admin-gated for
// everything else — after reading the body, and it calls
// host.Middleware().ResolveAdmin(r) by hand. The exact same seam already
// forced the must-change-password gate to be hand-copied into this handler.
//
// It is a SHARPER lever than suspend: what the attacker gets is an OAuth
// client of their own with attacker-chosen redirect_uris, registered under the
// victim deployment, which is a standing credential rather than a one-off
// write. So the assertion is on persistence — no client row — not on a status
// code alone.
func TestCrossSiteWrite_DCRRegisterRefused(t *testing.T) {
	dcr := func(t *testing.T) *xsFixture {
		return newXSFixture(t, xsSameSiteNone, oauth2server.New(oauth2server.Config{
			Issuer:      "http://idp.test",
			BasePath:    "/api/auth",
			AuthCodeTTL: time.Minute,
			DCREnabled:  true,
		}))
	}
	// A NON-loopback redirect_uri: that is what forces the admin-gated branch
	// (a loopback-only public client may self-register anonymously, and would
	// carry no ambient authority to abuse).
	const body = `{"redirect_uris":["https://evil.example/cb"],"token_endpoint_auth_method":"none"}`

	clients := func(t *testing.T, f *xsFixture) int {
		t.Helper()
		cs, err := f.h.repo.ListOAuth2Clients(context.Background())
		if err != nil {
			t.Fatalf("list clients: %v", err)
		}
		return len(cs)
	}

	f := dcr(t)
	code, resp := f.do(t, xsReq{
		method:  http.MethodPost,
		path:    "/oauth/register",
		body:    body,
		ctype:   "application/json",
		cookie:  f.adminCookie,
		headers: crossSiteHeaders,
	})
	if n := clients(t, f); n != 0 {
		t.Errorf("a cross-site POST /oauth/register on the admin's ambient cookie REGISTERED %d "+
			"OAuth client(s) with attacker-chosen redirect_uris", n)
	}
	if code != http.StatusForbidden {
		t.Errorf("cross-site DCR registration returned %d, want 403; body=%s", code, resp)
	}
	// This endpoint answers in RFC 7591 §3.2.2 shape, not problem+json — but
	// the operator-facing escape hatches must still be in the body.
	var errBody struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
		Detail      string `json:"detail"`
	}
	_ = json.Unmarshal([]byte(resp), &errBody)
	if errBody.Error != "access_denied" {
		t.Errorf("error = %q, want access_denied (body=%s)", errBody.Error, resp)
	}
	if errBody.Detail != "" {
		t.Errorf("body must stay RFC 7591 §3.2.2, not problem+json: %s", resp)
	}
	if errBody.Description != middleware.CrossSiteWriteDetail {
		t.Errorf("error_description = %q, want middleware.CrossSiteWriteDetail", errBody.Description)
	}

	// POSITIVE CONTROL: the same registration from the first-party console
	// still succeeds and still persists the client.
	ok := dcr(t)
	code, resp = ok.do(t, xsReq{
		method: http.MethodPost,
		path:   "/oauth/register",
		body:   body,
		ctype:  "application/json",
		cookie: ok.adminCookie,
		headers: map[string]string{
			"Origin":         ok.h.srv.URL,
			"Sec-Fetch-Site": "same-origin",
		},
	})
	if code != http.StatusCreated {
		t.Fatalf("same-origin admin DCR registration refused: %d %s", code, resp)
	}
	if n := clients(t, ok); n != 1 {
		t.Fatalf("same-origin admin DCR registration returned 201 but persisted %d clients", n)
	}
}

// ---------------------------------------------------------------------------
// 5. The kill switch
// ---------------------------------------------------------------------------

// TestCrossSiteWrite_KillSwitch: this is the highest-blast-radius refusal in
// the library, so the escape hatch the 403 body advertises has to actually
// work — an operator paged at 2am must be able to restore the previous
// behaviour from config alone. server.cross_site_writes.allow: true makes the
// verbatim exploit request succeed again.
func TestCrossSiteWrite_KillSwitch(t *testing.T) {
	f := newXSFixture(t, func(cfg *yauth.YAuthConfig) {
		xsSameSiteNone(cfg)
		cfg.CrossSiteWrites = yauth.CrossSiteWriteConfig{Allow: true}
	})

	code, body := f.do(t, xsReq{
		method:  http.MethodPost,
		path:    "/admin/users/" + f.victimID + "/suspend",
		cookie:  f.adminCookie,
		headers: crossSiteHeaders,
	})
	if code != http.StatusOK {
		t.Fatalf("cross_site_writes.allow=true still refused the write: %d %s", code, body)
	}
	if f.victim(t).SuspendedAt == nil {
		t.Fatalf("cross_site_writes.allow=true returned 200 but did not suspend the user")
	}
}
