package ssosaml

import (
	"bytes"
	"compress/flate"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// Standing fuzz coverage for the three places this plugin decodes XML that
// nobody has authenticated yet. None of these targets found a defect; they
// exist so a future edit cannot introduce one unnoticed.
//
// The ACS handler (handlers_login.go) is a PUBLIC route: anyone who can reach
// the deployment can POST a SAMLResponse to it. Before crewjam/saml verifies a
// single signature, two of our own decoders have already run on the attacker's
// bytes:
//
//   - peekResponseIssuer / scanFirstIssuer base64-decode the form value and run
//     an UNVERIFIED stdlib XML scan for the first <Issuer>. On current main the
//     ACS handler calls it at handlers_login.go:377 — on the unsolicited path,
//     after RelayState-based connection lookup has already failed, purely to
//     produce an operator breadcrumb. The return value is discarded, but the
//     PARSE still happens, on bytes from an unauthenticated POST to a public
//     route, and before any signature has been checked. Routing by issuer is
//     documented there as a future enhancement, which would move this decoder
//     onto the main path.
//   - inflateSAML (slo.go:252) base64-decodes and raw-DEFLATE-inflates the
//     redirect-binding SAMLRequest on /slo, likewise before verification. Its
//     output is bounded by io.LimitReader(fr, 1<<20); this harness is what
//     keeps that bound honest.
//
// A panic in either is an unauthenticated request-path DoS, and a hang (a
// decompression bomb, a decoder that never advances) is the same thing more
// slowly. Those two properties — returns, does not panic — are what the
// mutator genuinely exercises here, because both decoders take raw bytes with
// no cryptographic gate in front of them.
//
// FuzzParseResponse goes one level deeper: it drives arbitrary base64 through a
// real httptest form POST into crewjam/saml's ParseResponse against a real
// ServiceProvider, and asserts that anything which survives that verification
// also survives OUR post-checks — validateAssertion plus the replay accounting
// that scopes the cache entry. An assertion that ParseResponse accepts but
// which makes validateAssertion or assertionValidUntil panic would be a
// verified-input crash on the login path.
//
// REACHABILITY of that deeper half, stated plainly: ParseResponse returns a nil
// error only for a document bearing a valid XML-DSig under the fuzz cert, and
// the harness never signs anything. No mutator will produce one. So everything
// past the `if err != nil { return }` in FuzzParseResponse — including the
// validateAssertion and replay calls — is a REGRESSION TRIPWIRE for a human
// editing this package, not a branch the fuzzer reaches. What -fuzz actually
// covers there is crewjam's pre-signature parse of our form POST. Per-input
// XML-DSig signing would fix that and is deliberately not attempted: it costs
// far more per exec than it buys.
//
// The harness deliberately does NOT call ssosaml.New(): it builds the plugin
// value directly, so nothing here depends on (or perturbs) process-wide state
// that New may come to own — crewjam exposes clock skew as a package-level
// var (saml.MaxClockSkew), and a fuzz target that ran for a minute while
// holding a process-wide knob would make every other test in this package
// order-dependent.
//
// It also carries its own certificate fixture rather than sharing
// ssosaml_test.go's selfSignedCert/newFakeIDP, so a later change to the IdP
// fixtures cannot silently move the ground under these targets.

// fuzzSelfSignedCertPEM mirrors selfSignedCert from ssosaml_test.go but takes a
// testing.TB (so *testing.F can use it during harness setup) and returns the
// PEM directly, which is the only form the config field wants. Kept local and
// self-contained — including the PEM encoding, rather than borrowing
// ssosaml_test.go's pemEncodeCert — so this file depends on no fixture another
// test in the package is free to change.
func fuzzSelfSignedCertPEM(tb testing.TB, key *rsa.PrivateKey, cn string) string {
	tb.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		tb.Fatalf("create cert: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// responseSkeleton is a structurally complete (unsigned) SAMLResponse. It is
// rejected on the real path — no signature — but it gives the mutator a valid
// XML shape to start from rather than random bytes.
const responseSkeleton = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_resp1" Version="2.0" IssueInstant="2026-01-01T00:00:00Z" Destination="https://sp.test/acs">
<saml:Issuer>https://idp.test/metadata</saml:Issuer>
<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
<saml:Assertion ID="_a1" Version="2.0" IssueInstant="2026-01-01T00:00:00Z">
<saml:Issuer>https://idp.test/metadata</saml:Issuer>
<saml:Subject><saml:NameID>alice@example.com</saml:NameID>
<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
<saml:SubjectConfirmationData InResponseTo="_req1" Recipient="https://sp.test/acs" NotOnOrAfter="2036-01-01T00:00:00Z"/>
</saml:SubjectConfirmation></saml:Subject>
<saml:Conditions NotBefore="2026-01-01T00:00:00Z" NotOnOrAfter="2036-01-01T00:00:00Z">
<saml:AudienceRestriction><saml:Audience>https://sp.test/metadata</saml:Audience></saml:AudienceRestriction>
</saml:Conditions>
</saml:Assertion></samlp:Response>`

// doctypeBomb is the classic entity-expansion document. Go's encoding/xml does
// not expand external or undeclared entities, but the seed keeps that property
// under test rather than assumed.
const doctypeBomb = `<?xml version="1.0"?><!DOCTYPE r [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;"><!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">]><r><Issuer>&c;</Issuer></r>`

func deepNest(depth int) string {
	var sb strings.Builder
	for i := 0; i < depth; i++ {
		sb.WriteString("<a>")
	}
	sb.WriteString("<Issuer>x</Issuer>")
	for i := 0; i < depth; i++ {
		sb.WriteString("</a>")
	}
	return sb.String()
}

// deflateB64 raw-DEFLATEs then base64-encodes payload, producing the exact
// wire form inflateSAML expects from a redirect-binding SAMLRequest.
func deflateB64(tb testing.TB, payload []byte) string {
	tb.Helper()
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.BestCompression)
	if err != nil {
		tb.Fatalf("flate.NewWriter: %v", err)
	}
	if _, err := w.Write(payload); err != nil {
		tb.Fatalf("deflate write: %v", err)
	}
	if err := w.Close(); err != nil {
		tb.Fatalf("deflate close: %v", err)
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

func xmlSeeds() []string {
	return []string{
		responseSkeleton,
		doctypeBomb,
		deepNest(5000),
		"",
		"<",
		"<Issuer",
		"<Issuer></Issuer>",
		"<Issuer>   spaced   </Issuer>",
		"<a><Issuer><b>nested</b>tail</Issuer></a>",
		"<Issuer xmlns:undeclared-prefix:x=\"y\">v</Issuer>",
		"<r><Issuer>&undeclared;</Issuer></r>",
		"<r><Issuer>\x00nul</Issuer></r>",
		"<?xml version=\"1.0\" encoding=\"UTF-7\"?><Issuer>x</Issuer>",
		"not xml at all",
	}
}

// FuzzScanFirstIssuer drives the unverified routing scan directly.
func FuzzScanFirstIssuer(f *testing.F) {
	for _, s := range xmlSeeds() {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		// The only contract is: returns, does not panic, and never hands back a
		// value carrying a NUL — the issuer is used as a lookup key and as half
		// of the replay cache's NUL-separated composite key (replay.go seenKey),
		// which a NUL in the issuer would let an attacker forge collisions in.
		got := scanFirstIssuer(raw)
		if strings.ContainsRune(got, '\x00') {
			t.Fatalf("scanFirstIssuer(%q) returned an issuer containing NUL: %q", raw, got)
		}
	})
}

// FuzzPeekResponseIssuer drives the base64 wrapper the ACS handler actually
// calls, so the decode step is in scope too.
func FuzzPeekResponseIssuer(f *testing.F) {
	for _, s := range xmlSeeds() {
		f.Add(base64.StdEncoding.EncodeToString([]byte(s)))
	}
	f.Add("")
	f.Add("not-base64!!")
	f.Add("AAAA")
	f.Fuzz(func(t *testing.T, b64 string) {
		issuer, err := peekResponseIssuer(b64)
		if err != nil {
			return
		}
		if strings.ContainsRune(issuer, '\x00') {
			t.Fatalf("peekResponseIssuer(%q) returned an issuer containing NUL: %q", b64, issuer)
		}
	})
}

// FuzzInflateSAML drives the redirect-binding SLO decoder. The property that
// matters is the 1 MiB ceiling: it is the only thing standing between a
// compressed SAMLRequest and unbounded allocation on a public GET.
//
// Be precise about what the size check below can and cannot do. While
// slo.go:252 reads through io.LimitReader(fr, 1<<20), a return over 1 MiB is
// impossible by construction, so `len(out) > 1<<20` can never fire — it is a
// TRIPWIRE for someone deleting that LimitReader, not something the mutator
// can trigger. What -fuzz genuinely exercises here is that inflateSAML always
// RETURNS: no panic on malformed base64 or a corrupt DEFLATE stream, and no
// hang on a bomb, which is why a seed inflates 8 MiB of zeroes.
//
// Worth stating because a reader of this file will otherwise assume otherwise:
// the bound is silent. inflateSAML returns a TRUNCATED 1 MiB with a NIL error,
// so its caller cannot distinguish a complete document from a clipped one, and
// a clipped document simply fails to parse downstream. That is safe, but it is
// truncation, not rejection.
func FuzzInflateSAML(f *testing.F) {
	f.Add("")
	f.Add("not-base64!!")
	f.Add("AAAA")
	f.Add(base64.StdEncoding.EncodeToString([]byte(responseSkeleton)))
	// A real deflate stream: zero-filled input compresses enormously, which is
	// exactly the shape the LimitReader exists for.
	f.Add(deflateB64(f, make([]byte, 8<<20)))
	f.Add(deflateB64(f, []byte(responseSkeleton)))

	f.Fuzz(func(t *testing.T, b64 string) {
		out, err := inflateSAML(b64)
		if err != nil {
			return
		}
		if len(out) > 1<<20 {
			t.Fatalf("inflateSAML(%d bytes of base64) returned %d bytes, above the 1 MiB ceiling", len(b64), len(out))
		}
	})
}

// FuzzParseResponse drives arbitrary base64 through a real ACS-shaped form POST
// into crewjam/saml's ParseResponse, then through our own post-verification
// checks. One ServiceProvider is shared across iterations — ParseResponse does
// not mutate it — and one keypair is generated at setup, not per input.
func FuzzParseResponse(f *testing.F) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		f.Fatalf("rsa.GenerateKey: %v", err)
	}
	certPEM := fuzzSelfSignedCertPEM(f, key, "idp.fuzz")

	cfg := SamlConnectionConfig{
		IdpEntityID:            "https://idp.test/metadata",
		IdpSsoURL:              "https://idp.test/sso",
		IdpX509Cert:            certPEM,
		SpEntityID:             "https://sp.test/metadata",
		SpAcsURL:               "https://sp.test/acs",
		IdpInitiatedSsoAllowed: true,
	}
	sp, err := buildServiceProvider(&cfg, "https://sp.test", "conn-fuzz", time.Minute)
	if err != nil {
		f.Fatalf("buildServiceProvider: %v", err)
	}
	p := &ssoSAMLPlugin{cfg: Config{ReplayCacheTTL: 5 * time.Minute, ClockSkew: time.Minute}}

	for _, s := range xmlSeeds() {
		f.Add(base64.StdEncoding.EncodeToString([]byte(s)))
	}
	f.Add("")
	f.Add("not-base64!!")

	f.Fuzz(func(t *testing.T, samlResponseB64 string) {
		form := url.Values{}
		form.Set("SAMLResponse", samlResponseB64)
		form.Set("RelayState", "cid:conn-fuzz")
		r := httptest.NewRequest(http.MethodPost, "https://sp.test/acs", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		assertion, err := sp.ParseResponse(r, []string{"_req1"})
		if err != nil {
			return
		}
		// Anything ParseResponse accepted is, by construction, signed by our own
		// fuzz key — which the harness never uses to sign, so this branch should
		// be unreachable. If a mutation ever does reach it, our own post-checks
		// must survive the input rather than panic.
		if assertion == nil {
			t.Fatalf("ParseResponse(%q) returned nil error and nil assertion", samlResponseB64)
		}
		_ = p.validateAssertion(assertion, &cfg)
		_ = p.replay().Seen(cfg.IdpEntityID, assertion.ID, assertionValidUntil(assertion))
	})
}
