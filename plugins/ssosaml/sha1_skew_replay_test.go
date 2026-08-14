// sha1_skew_replay_test.go — three related holes in the SAML SP, all of
// which let the IdP (or anyone who can forge for it) pick security
// parameters that yauth believes it is choosing itself.
//
//  1. SHA-1 XML signatures are accepted on the assertion path.
//     buildServiceProvider (sp.go) leaves saml.ServiceProvider.SignatureVerifier
//     nil, so crewjam's validateSignature falls through to
//     dsig.NewDefaultValidationContext(...).Validate(el). goxmldsig v1.6.0's
//     default context carries NO algorithm allow-list: RSA-SHA1 signatures and
//     SHA-1 digests are in its identifier tables and are verified happily. The
//     sp.SignatureMethod = rsa-sha256 line in sp.go pins the algorithm for
//     OUTBOUND AuthnRequests only; it says nothing about what we ACCEPT.
//     This is not hypothetical for this repo: crewjam's own IdentityProvider
//     falls back to dsig.RSASHA1SignatureMethod when SignatureMethod is empty
//     (identity_provider.go:1112-1114) and newFakeIDP never sets it — so every
//     assertion the existing ssosaml suite verifies today is RSA-SHA1 signed
//     and every one is accepted. The tests below set it explicitly only so the
//     intent is legible; deleting that line does not change the outcome.
//     The same hole is explicit on the SLO path: verifyRedirectSignature
//     (slo.go) has a hard-coded rsa-sha1 arm with no gate at all.
//
//  2. Config.ClockSkew is accepted, defaulted, threaded through five call
//     sites — and never read. buildServiceProvider takes it as a parameter
//     whose body never mentions it. crewjam scopes the real knobs as
//     package-level vars (saml.MaxIssueDelay, saml.MaxClockSkew), so the
//     effective skew is 180s no matter what an embedder configures, and the
//     documented 1-minute default is a lie. An assertion whose NotBefore is
//     two minutes in the future is accepted by /sso/saml/acs today.
//
//  3. The replay cache lets the IdP size yauth's memory. replayCache.Seen
//     stores exp = validUntil + ttl, where validUntil is
//     assertionValidUntil(assertion) = the assertion's Conditions/@NotOnOrAfter
//     — a value the IdP writes and crewjam never bounds from above. gcLocked
//     only evicts entries already past exp, so an IdP that stamps
//     NotOnOrAfter a century out pins entries in a map shared by every
//     connection in the process, and makes gcLocked's O(n) sweep run over all
//     of them on every subsequent assertion.
//
// Each refusal test below is paired with a positive control on the same
// fixture, so a "fix" that simply breaks SAML login, SLO or replay dedupe
// cannot make this file pass.
package ssosaml

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	"github.com/google/uuid"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/yackey-labs/yauth/auth"
	"github.com/yackey-labs/yauth/domain"
)

// Algorithm identifiers, spelled out rather than imported from goxmldsig so
// this file adds no module dependency of its own.
const (
	algRSASHA1   = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
	algRSASHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
)

// postSignedResponse drives the SP-initiated flow to the ACS with whatever
// the fixture IdP is currently configured to mint, and returns the ACS
// response. It is the existing beginLogin + signedResponseFor pair, wrapped.
func postSignedResponse(t *testing.T, f *e2eFixture) *http.Response {
	t.Helper()
	st := beginLogin(t, f)
	respB64, _ := f.idp.signedResponseFor(t, f.sp, st.PKCEVerifier, st.State)
	form := url.Values{"SAMLResponse": {respB64}, "RelayState": {st.State}}
	resp, err := newNoRedirectClient().PostForm(f.srv.URL+"/sso/saml/acs", form)
	if err != nil {
		t.Fatalf("post to acs: %v", err)
	}
	return resp
}

func sessionCookie(resp *http.Response) *http.Cookie {
	for _, c := range resp.Cookies() {
		if c.Name == "yauth_session" && c.Value != "" {
			return c
		}
	}
	return nil
}

// --- 1. SHA-1 on the assertion path -----------------------------------

// TestSAML_SHA1SignedAssertionIsRefused: the IdP signs the Response and
// Assertion with RSA-SHA1 — which is exactly what a crewjam-based IdP,
// ADFS 2.0 or a legacy Shibboleth deployment does by default. yauth must
// refuse it, and must not mint a session or JIT-provision a user off it.
func TestSAML_SHA1SignedAssertionIsRefused(t *testing.T) {
	f := newE2E(t)
	// Explicit for legibility only: leaving this unset produces the same
	// RSA-SHA1 signature, because that is crewjam's IdP default.
	f.idp.idp.SignatureMethod = algRSASHA1

	resp := postSignedResponse(t, f)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("SHA-1 signed assertion accepted: status=%d body=%s", resp.StatusCode, string(body))
	}
	// The assertions that matter: no credential of any kind came out of it.
	if c := sessionCookie(resp); c != nil {
		t.Errorf("SHA-1 signed assertion set a session cookie (%d bytes of session token)", len(c.Value))
	}
	if u, err := f.repo.GetUserByEmail(context.Background(), "alice@example.com"); err == nil && u != nil {
		t.Errorf("SHA-1 signed assertion JIT-provisioned user %s (%s)", u.ID, u.Email)
	}
}

// TestSAML_SHA256AssertionStillAccepted is the positive control for the test
// above: the identical fixture, signing with RSA-SHA256, must still complete
// the login end to end. A "fix" that refuses all XML signatures fails here.
func TestSAML_SHA256AssertionStillAccepted(t *testing.T) {
	f := newE2E(t)
	f.idp.idp.SignatureMethod = algRSASHA256

	resp := postSignedResponse(t, f)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("RSA-SHA256 assertion refused: status=%d body=%s", resp.StatusCode, string(body))
	}
	if sessionCookie(resp) == nil {
		t.Fatal("RSA-SHA256 assertion set no session cookie")
	}
	u, err := f.repo.GetUserByEmail(context.Background(), "alice@example.com")
	if err != nil || u == nil {
		t.Fatalf("RSA-SHA256 assertion did not JIT-provision the user: err=%v u=%v", err, u)
	}
}

// TestSAML_SHA1AcceptedWhenConnectionOptsIn is the escape hatch, and it is
// driven through the admin API on purpose rather than by mutating the struct.
//
// The refusal above is BREAKING for anyone still wired to an ADFS 2.0 /
// Shibboleth 2.x / crewjam-default IdP, so the hatch has to be genuinely
// reachable by an operator: PATCH the connection, log in, done. Reaching it
// through PATCH is what makes the test load-bearing — SamlConnectionConfig
// and persistedConfig are two structs joined by a field-by-field codec, so a
// flag declared on only the first is silently dropped on write and reads back
// false. A struct-literal test would have passed against exactly that bug.
func TestSAML_SHA1AcceptedWhenConnectionOptsIn(t *testing.T) {
	f := newE2E(t)
	ctx := context.Background()

	// Authenticate as the org owner seeded by the fixture so the admin
	// CRUD route's requireOrgAdmin gate is satisfied.
	admin, err := f.repo.GetUserByEmail(ctx, "admin@example.com")
	if err != nil || admin == nil {
		t.Fatalf("fixture precondition: seeded admin missing: %v", err)
	}
	f.host.mw.AddResolver(&stubResolver{user: &domain.AuthUser{User: *admin}})

	// The PATCH merge applies every bool unconditionally, so the two
	// signed-required flags are resent to keep them true — otherwise this
	// "positive control" would quietly be testing an unsigned-assertion
	// connection instead.
	resp := doJSON(t, http.MethodPatch,
		f.srv.URL+"/organizations/"+f.org.ID+"/sso/saml/connections/"+f.conn.ID,
		map[string]any{
			"saml": map[string]any{
				"allow_sha1_signatures":     true,
				"assertion_signed_required": true,
				"response_signed_required":  true,
			},
		})
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PATCH allow_sha1_signatures: status=%d body=%s", resp.StatusCode, string(body))
	}
	// The flag must survive the round-trip through persistence, not just
	// the request decode.
	var updated struct {
		SAML struct {
			AllowSHA1Signatures bool `json:"allow_sha1_signatures"`
		} `json:"saml"`
	}
	if err := json.Unmarshal(body, &updated); err != nil {
		t.Fatalf("decode PATCH response: %v (%s)", err, string(body))
	}
	if !updated.SAML.AllowSHA1Signatures {
		t.Fatalf("allow_sha1_signatures did not persist; the hatch is unreachable: %s", string(body))
	}

	// Now the SHA-1 login that TestSAML_SHA1SignedAssertionIsRefused
	// refuses must succeed.
	f.idp.idp.SignatureMethod = algRSASHA1
	lresp := postSignedResponse(t, f)
	defer lresp.Body.Close()
	lbody, _ := io.ReadAll(lresp.Body)

	if lresp.StatusCode != http.StatusFound {
		t.Fatalf("opted-in connection refused a SHA-1 assertion: status=%d body=%s", lresp.StatusCode, string(lbody))
	}
	if sessionCookie(lresp) == nil {
		t.Fatal("opted-in SHA-1 login set no session cookie")
	}
	if u, err := f.repo.GetUserByEmail(ctx, "alice@example.com"); err != nil || u == nil {
		t.Fatalf("opted-in SHA-1 login did not JIT-provision the user: err=%v u=%v", err, u)
	}
}

// TestSAML_SHA1GuardReadsNestedSignatures pins the one design decision in
// algDenyListVerifier that is easy to "simplify" away.
//
// goxmldsig's findSignature walks the WHOLE subtree and validates the FIRST
// <Signature> it finds, depth-first — NOT necessarily the element's direct
// child. A guard written as ./Signature/SignedInfo/SignatureMethod would
// therefore read a decoy: an attacker nests the forged RSA-SHA1 Signature
// inside <saml:Issuer> (found first, and the one actually verified) and hangs
// an innocuous RSA-SHA256 Signature off the root for the guard to approve.
// The verifier uses descendant paths (".//") for exactly this reason.
//
// Paired positive control below: an element carrying only SHA-256 identifiers
// must get PAST the algorithm gate and fail for some other reason, so a guard
// that simply errors on everything cannot pass this file.
func TestSAML_SHA1GuardReadsNestedSignatures(t *testing.T) {
	const decoyed = `<Response xmlns="urn:oasis:names:tc:SAML:2.0:protocol">` +
		`<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">` +
		`<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo>` +
		`<ds:SignatureMethod Algorithm="` + algRSASHA1 + `"/>` +
		`<ds:Reference><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/></ds:Reference>` +
		`</ds:SignedInfo></ds:Signature></saml:Issuer>` +
		`<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo>` +
		`<ds:SignatureMethod Algorithm="` + algRSASHA256 + `"/>` +
		`<ds:Reference><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/></ds:Reference>` +
		`</ds:SignedInfo></ds:Signature></Response>`

	doc := etree.NewDocument()
	if err := doc.ReadFromString(decoyed); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	v := algDenyListVerifier{allowSHA1: false}
	// vc is never reached on the refusal path, so a nil context is safe
	// here and proves the guard short-circuits before delegating.
	err := v.VerifySignature(nil, doc.Root())
	if err == nil || !strings.Contains(err.Error(), "allow_sha1_signatures") {
		t.Fatalf("nested SHA-1 Signature not refused (a direct-child-only guard would miss it): err=%v", err)
	}

	// Positive control: nothing SHA-1 anywhere, so the guard must fall
	// through to the real validation context rather than refusing.
	const clean = `<Response xmlns="urn:oasis:names:tc:SAML:2.0:protocol">` +
		`<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo>` +
		`<ds:SignatureMethod Algorithm="` + algRSASHA256 + `"/>` +
		`<ds:Reference><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/></ds:Reference>` +
		`</ds:SignedInfo></ds:Signature></Response>`
	doc2 := etree.NewDocument()
	if err := doc2.ReadFromString(clean); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	vc := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{})
	err = v.VerifySignature(vc, doc2.Root())
	if err != nil && strings.Contains(err.Error(), "allow_sha1_signatures") {
		t.Fatalf("SHA-256-only element refused by the SHA-1 guard: %v", err)
	}
}

// --- 1b. SHA-1 on the SLO path ----------------------------------------

// signedRedirectLogoutRequestAlg mirrors slo_test.go's helper but lets the
// caller pick the SigAlg, so the rsa-sha1 arm of verifyRedirectSignature can
// be exercised directly.
func signedRedirectLogoutRequestAlg(t *testing.T, idpKey *rsa.PrivateKey, idpEntityID, nameID, sigAlg string) string {
	t.Helper()
	xmlReq := `<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_` + uuid.NewString() + `" Version="2.0" IssueInstant="` + time.Now().UTC().Format(time.RFC3339) + `"><saml:Issuer>` + idpEntityID + `</saml:Issuer><saml:NameID>` + nameID + `</saml:NameID></samlp:LogoutRequest>`

	var buf bytes.Buffer
	fw, _ := flate.NewWriter(&buf, flate.DefaultCompression)
	_, _ = fw.Write([]byte(xmlReq))
	_ = fw.Close()
	samlRequest := base64.StdEncoding.EncodeToString(buf.Bytes())

	signedStr := "SAMLRequest=" + url.QueryEscape(samlRequest) + "&SigAlg=" + url.QueryEscape(sigAlg)

	var (
		hash   crypto.Hash
		digest []byte
	)
	switch sigAlg {
	case algRSASHA1:
		hash = crypto.SHA1
		s := sha1.Sum([]byte(signedStr))
		digest = s[:]
	case algRSASHA256:
		hash = crypto.SHA256
		s := sha256.Sum256([]byte(signedStr))
		digest = s[:]
	default:
		t.Fatalf("unhandled sigAlg %q", sigAlg)
	}
	sig, err := rsa.SignPKCS1v15(rand.Reader, idpKey, hash, digest)
	if err != nil {
		t.Fatalf("sign logout request: %v", err)
	}

	return "SAMLRequest=" + url.QueryEscape(samlRequest) +
		"&SigAlg=" + url.QueryEscape(sigAlg) +
		"&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(sig))
}

// TestSAML_SLORefusesSHA1RedirectSignature: a LogoutRequest whose redirect-
// binding signature is RSA-SHA1 must not be honoured — the user's session
// must survive it. Front-channel logout is a lower-value target than login,
// but it is still an unauthenticated endpoint that terminates sessions on a
// signature we are willing to verify with a broken hash.
func TestSAML_SLORefusesSHA1RedirectSignature(t *testing.T) {
	srv, r, idpKey, idpEntityID, _, rawSession := sloTestEnv(t)
	ctx := context.Background()

	if _, err := r.GetSessionByTokenHash(ctx, auth.HashToken(rawSession)); err != nil {
		t.Fatalf("precondition: session must exist: %v", err)
	}

	q := signedRedirectLogoutRequestAlg(t, idpKey, idpEntityID, "user-nameid-1", algRSASHA1)
	resp, err := http.Get(srv.URL + "/sso/saml/slo?" + q)
	if err != nil {
		t.Fatalf("slo GET: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	// The assertion that matters: the session is still there.
	if _, err := r.GetSessionByTokenHash(ctx, auth.HashToken(rawSession)); err != nil {
		t.Errorf("SHA-1 signed LogoutRequest revoked the session (status=%d body=%q)", resp.StatusCode, string(body))
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("SHA-1 signed LogoutRequest: expected 400, got %d body=%q", resp.StatusCode, string(body))
	}
}

// TestSAML_SLOAcceptsSHA256RedirectSignature is the positive control: the
// same helper, same fixture, RSA-SHA256 — logout must still work.
func TestSAML_SLOAcceptsSHA256RedirectSignature(t *testing.T) {
	srv, r, idpKey, idpEntityID, _, rawSession := sloTestEnv(t)
	ctx := context.Background()

	q := signedRedirectLogoutRequestAlg(t, idpKey, idpEntityID, "user-nameid-1", algRSASHA256)
	resp, err := http.Get(srv.URL + "/sso/saml/slo?" + q)
	if err != nil {
		t.Fatalf("slo GET: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusFound {
		t.Fatalf("RSA-SHA256 LogoutRequest refused: status=%d body=%q", resp.StatusCode, string(body))
	}
	if _, err := r.GetSessionByTokenHash(ctx, auth.HashToken(rawSession)); err == nil {
		t.Fatal("RSA-SHA256 LogoutRequest did not revoke the session")
	}
}

// --- 2. ClockSkew ------------------------------------------------------

// TestSAML_ConfiguredClockSkewIsHonoured asserts the configured skew actually
// reaches the only place that can enforce it.
//
// NOT PARALLEL-SAFE, deliberately: saml.MaxClockSkew is a package-level var
// in crewjam/saml, so this test observes process-wide state. That is itself
// part of the finding — the knob yauth must set is global, and whoever fixes
// this has to say so out loud rather than pretend it is per-connection.
func TestSAML_ConfiguredClockSkewIsHonoured(t *testing.T) {
	// Once New() owns this var, leaving 30s behind would silently retune
	// every later test in the package.
	restore := saml.MaxClockSkew
	t.Cleanup(func() { saml.MaxClockSkew = restore })

	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}
	const want = 30 * time.Second
	if _, err := New(Config{
		EncryptionKey:   key,
		AuthnRequestTTL: 5 * time.Minute,
		ReplayCacheTTL:  5 * time.Minute,
		ClockSkew:       want,
	}); err != nil {
		t.Fatal(err)
	}
	if saml.MaxClockSkew != want {
		t.Fatalf("Config.ClockSkew is discarded: configured %v, effective skew is %v", want, saml.MaxClockSkew)
	}
}

// TestSAML_FutureDatedAssertionOutsideConfiguredSkewIsRefused is the
// behavioural half. The fixture plugin is built with ClockSkew: 1 minute
// (newPlugin), and the IdP stamps Conditions/@NotBefore two minutes in the
// future. Under the configured skew that assertion is not yet valid; under
// crewjam's un-overridden 180s default it sails through.
//
// Same parallel-hostility note as above.
func TestSAML_FutureDatedAssertionOutsideConfiguredSkewIsRefused(t *testing.T) {
	f := newE2E(t)
	if f.plugin.cfg.ClockSkew != time.Minute {
		t.Fatalf("fixture precondition: expected 1m ClockSkew, got %v", f.plugin.cfg.ClockSkew)
	}
	f.idp.idp.SignatureMethod = algRSASHA256 // isolate this from finding #1
	nbf := time.Now().Add(2 * time.Minute)
	f.idp.overrideAssertNBF = &nbf

	resp := postSignedResponse(t, f)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("assertion dated %v in the future accepted under a 1m configured skew: status=%d body=%s",
			2*time.Minute, resp.StatusCode, string(body))
	}
	if c := sessionCookie(resp); c != nil {
		t.Errorf("future-dated assertion set a session cookie (%d bytes)", len(c.Value))
	}
	if u, err := f.repo.GetUserByEmail(context.Background(), "alice@example.com"); err == nil && u != nil {
		t.Errorf("future-dated assertion JIT-provisioned user %s", u.ID)
	}
}

// TestSAML_AssertionWithinConfiguredSkewIsAccepted is the positive control
// for the skew tests: a NotBefore 30 seconds in the future is inside the
// configured 1-minute skew and must still log in. A fix that clamps skew to
// zero, or that tightens MaxIssueDelay along with it, fails here.
func TestSAML_AssertionWithinConfiguredSkewIsAccepted(t *testing.T) {
	f := newE2E(t)
	f.idp.idp.SignatureMethod = algRSASHA256
	nbf := time.Now().Add(30 * time.Second)
	f.idp.overrideAssertNBF = &nbf

	resp := postSignedResponse(t, f)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("assertion inside the configured skew refused: status=%d body=%s", resp.StatusCode, string(body))
	}
	if sessionCookie(resp) == nil {
		t.Fatal("assertion inside the configured skew set no session cookie")
	}
}

// --- 3. IdP-chosen replay-cache entry lifetime -------------------------

// entryLifetimes reads the cache's stored expiries. In-package white-box
// access is deliberate: the defect is precisely the VALUE stored, and there
// is no way to observe an entry that outlives the process from outside.
func entryLifetimes(c *replayCache, now time.Time) (worstKey string, worst time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, exp := range c.seen {
		if life := exp.Sub(now); life > worst {
			worst, worstKey = life, k
		}
	}
	return worstKey, worst
}

// TestSAML_ReplayEntryLifetimeIsClamped: the IdP writes NotOnOrAfter, yauth
// stores NotOnOrAfter + ttl as the entry's expiry, and gcLocked only evicts
// entries already past it. An IdP that stamps a far-future NotOnOrAfter
// therefore pins entries in a map shared by every SAML connection in the
// process — for as long as the process lives.
//
// The ceiling asserted here is deliberately generous (24h). Any sane clamp
// passes it; today's behaviour misses it by three orders of magnitude.
func TestSAML_ReplayEntryLifetimeIsClamped(t *testing.T) {
	c := newReplayCache(5 * time.Minute)
	const issuer = "https://idp.test/saml"
	// NotOnOrAfter as the IdP chose it. (A century, not the millennium the
	// finding describes, only because a millennium in nanoseconds overflows
	// time.Duration and would muddy the failure message.)
	far := time.Now().AddDate(100, 0, 0)
	for i := 0; i < 1000; i++ {
		c.Seen(issuer, fmt.Sprintf("_a%d", i), far)
	}
	// Force a gc sweep, as a subsequent assertion would.
	c.Seen(issuer, "_gc", time.Now())

	now := time.Now()
	key, worst := entryLifetimes(c, now)
	const ceiling = 24 * time.Hour
	if worst > ceiling {
		t.Errorf("IdP-chosen NotOnOrAfter pinned replay entry %q for %v (ceiling %v); %d entries are held and gcLocked now sweeps all of them on every assertion",
			strings.ReplaceAll(key, "\x00", "|"), worst.Round(time.Hour), ceiling, c.Len())
	}
}

// TestSAML_ReplayStillDedupesInsideTheAssertionWindow is the positive
// control: clamping the entry lifetime must not shorten it below the
// assertion's own validity window, or the replay cache stops catching
// replays — which is the whole point of the cache.
func TestSAML_ReplayStillDedupesInsideTheAssertionWindow(t *testing.T) {
	c := newReplayCache(5 * time.Minute)
	const issuer = "https://idp.test/saml"
	validUntil := time.Now().Add(5 * time.Minute)

	if c.Seen(issuer, "_normal", validUntil) {
		t.Fatal("first delivery of an assertion id reported as a replay")
	}
	if !c.Seen(issuer, "_normal", validUntil) {
		t.Fatal("second delivery of the same assertion id was NOT reported as a replay")
	}
	// The entry must still cover the assertion's own validity window.
	if _, worst := entryLifetimes(c, time.Now()); worst < 5*time.Minute {
		t.Fatalf("replay entry expires in %v, before the assertion's own NotOnOrAfter (5m); replays inside the window would be admitted", worst)
	}
}

// TestSAML_ReplayCacheIsNotUnboundedAcrossTenants states the shared-map half
// plainly: one connection's IdP must not be able to grow the process-wide
// cache that every other tenant's connection shares.
func TestSAML_ReplayCacheIsNotUnboundedAcrossTenants(t *testing.T) {
	p := newPlugin(t)
	c := p.replay()
	far := time.Now().AddDate(100, 0, 0)
	for i := 0; i < 500; i++ {
		c.Seen("https://tenant-a-idp.test/saml", fmt.Sprintf("_a%d", i), far)
	}
	// A well-behaved tenant's assertion arrives next; its gc sweep should
	// have cleared out the hostile tenant's entries long before now.
	c.Seen("https://tenant-b-idp.test/saml", "_b1", time.Now().Add(5*time.Minute))

	if _, worst := entryLifetimes(c, time.Now()); worst > 24*time.Hour {
		t.Errorf("tenant A's IdP pinned %d entries in the shared replay cache for up to %v",
			c.Len(), worst.Round(time.Hour))
	}
}
