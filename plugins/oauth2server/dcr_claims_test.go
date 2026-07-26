// Claim-extraction tests for DCR software_statement attestation.
//
// These live in `package oauth2server` because claim/stringClaim are
// unexported, and they exist because the jwx v2→v3 upgrade INVERTED the
// signal these helpers wrap:
//
//	v2: value, ok := tok.Get(key)   // absent → ok == false
//	v3: err := tok.Get(key, &dst)   // absent → err != nil
//
// A translation that conflates "claim absent" with "claim present" compiles
// cleanly and produces an attested statement asserting things the issuer
// never signed. Nothing else in the suite covers that, so it is pinned here.

package oauth2server

import (
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwt"
)

// tokenWith builds an unsigned token carrying the given claims.
func tokenWith(t *testing.T, claims map[string]any) jwt.Token {
	t.Helper()
	b := jwt.NewBuilder()
	for k, v := range claims {
		b = b.Claim(k, v)
	}
	tok, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestClaim_AbsentIsReportedAbsent(t *testing.T) {
	tok := tokenWith(t, map[string]any{"client_name": "Peer App"})

	if _, ok := claim(tok, "redirect_uris"); ok {
		t.Error("an absent claim must report ok=false — reporting it present would attest metadata the issuer never signed")
	}
	if v, ok := claim(tok, "client_name"); !ok || v != "Peer App" {
		t.Errorf("a present claim must round-trip, got v=%v ok=%v", v, ok)
	}
}

// The distinction that matters for attestation: an omitted redirect_uris must
// leave RedirectURIs nil, never an empty-but-present slice.
func TestStringClaim_AbsentYieldsEmptyNotFabricated(t *testing.T) {
	tok := tokenWith(t, map[string]any{"scope": "openid email"})

	if got := stringClaim(tok, "client_name"); got != "" {
		t.Errorf("absent claim should yield \"\", got %q", got)
	}
	if got := stringClaim(tok, "scope"); got != "openid email" {
		t.Errorf("present claim should round-trip, got %q", got)
	}
}

// v2 required BOTH the presence check and the string type assertion to pass
// before assigning. A non-string claim must therefore still yield "" rather
// than a coerced value.
func TestStringClaim_PresentButNotAStringYieldsEmpty(t *testing.T) {
	tok := tokenWith(t, map[string]any{
		"client_name": 42,
		"scope":       []string{"openid"},
	})

	if got := stringClaim(tok, "client_name"); got != "" {
		t.Errorf("numeric claim should not coerce to a string, got %q", got)
	}
	if got := stringClaim(tok, "scope"); got != "" {
		t.Errorf("array claim should not coerce to a string, got %q", got)
	}
}

// The full extraction shape used by verifyStatementSignature: a statement
// that omits every optional claim must attest nothing beyond the issuer.
func TestClaimExtraction_OmittedOptionalClaimsAttestNothing(t *testing.T) {
	tok := tokenWith(t, map[string]any{"iss": "https://peer.example.com"})

	out := &trustedStatement{}
	if v, ok := claim(tok, "redirect_uris"); ok {
		out.RedirectURIs = toStringSlice(v)
	}
	out.ClientName = stringClaim(tok, "client_name")
	out.Scope = stringClaim(tok, "scope")
	out.InitiateLoginURI = stringClaim(tok, "initiate_login_uri")
	out.ReturnURI = stringClaim(tok, "return_uri")

	if out.RedirectURIs != nil {
		t.Errorf("RedirectURIs must stay nil when the claim is absent, got %#v", out.RedirectURIs)
	}
	if out.ClientName != "" || out.Scope != "" || out.InitiateLoginURI != "" || out.ReturnURI != "" {
		t.Errorf("no optional field may be populated from an absent claim: %+v", out)
	}
}
