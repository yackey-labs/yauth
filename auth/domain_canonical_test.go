package auth

import (
	"context"
	"testing"
	"time"

	"github.com/yackey-labs/yauth/domain"
)

// Failing-test-first for LOW — domain canonicalization (IDNA/trailing dot).
// VerifyDomainTXT + ExtractEmailDomain only Lower+TrimSpace; they must also
// strip a single trailing dot and punycode-encode non-ASCII names.
func TestVerifyDomainTXT_TrailingDotEquivalent(t *testing.T) {
	r := &fakeTXTResolver{records: map[string][]string{
		"_yauth-domain-verify.acme.com": {"yauth-verify=t"},
	}}
	for _, dom := range []string{"ACME.com.", "acme.com", "  ACME.com.  "} {
		ok, err := VerifyDomainTXT(context.Background(), r, dom, "yauth-verify=t")
		if err != nil {
			t.Fatalf("%q: err %v", dom, err)
		}
		if !ok {
			t.Fatalf("%q: expected canonicalized lookup to match acme.com", dom)
		}
	}
}

func TestVerifyDomainTXT_IDNAEquivalent(t *testing.T) {
	r := &fakeTXTResolver{records: map[string][]string{
		"_yauth-domain-verify.xn--mnchen-3ya.de": {"yauth-verify=t"},
	}}
	for _, dom := range []string{"münchen.de", "MÜNCHEN.DE", "münchen.de.", "xn--mnchen-3ya.de"} {
		ok, err := VerifyDomainTXT(context.Background(), r, dom, "yauth-verify=t")
		if err != nil {
			t.Fatalf("%q: err %v", dom, err)
		}
		if !ok {
			t.Fatalf("%q: expected IDNA-canonicalized lookup to match punycode row", dom)
		}
	}
}

func TestVerifyDomainTXT_CanonicalMismatchStillRejected(t *testing.T) {
	r := &fakeTXTResolver{records: map[string][]string{
		"_yauth-domain-verify.acme.com": {"yauth-verify=t"},
	}}
	ok, err := VerifyDomainTXT(context.Background(), r, "evil.com.", "yauth-verify=t")
	if err != nil {
		t.Fatalf("err %v", err)
	}
	if ok {
		t.Fatalf("different domain must not match after canonicalization")
	}
}

func TestExtractEmailDomain_Canonicalizes(t *testing.T) {
	cases := map[string]string{
		"alice@ACME.COM.":  "acme.com",
		"alice@acme.com":   "acme.com",
		"user@münchen.de":  "xn--mnchen-3ya.de",
		"user@MÜNCHEN.DE.": "xn--mnchen-3ya.de",
	}
	for email, want := range cases {
		got, ok := ExtractEmailDomain(email)
		if !ok {
			t.Fatalf("%q: expected ok", email)
		}
		if got != want {
			t.Fatalf("%q: got %q want %q", email, got, want)
		}
	}
}

func TestAutoJoinFromEmail_TrailingDotAndIDNAEquivalent(t *testing.T) {
	ctx := context.Background()
	r := newMemForAutoJoin(t)
	seedOrg(t, r, "org1", "Acme", "acme")
	seedDomain(t, r, "org1", "acme.com", domain.DomainVerified, true, false, "member")
	seedOrg(t, r, "org2", "Munich", "munich")
	seedDomain(t, r, "org2", "xn--mnchen-3ya.de", domain.DomainVerified, true, false, "member")

	// Trailing-dot + case variant must still reach the stored row.
	results, err := AutoJoinFromEmail(ctx, r, "u1", "alice@ACME.com.", true, time.Now().UTC())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(results) != 1 || results[0].OrganizationID != "org1" {
		t.Fatalf("trailing-dot email must autojoin org1; got %+v", results)
	}

	// Unicode email must reach the punycode-stored row.
	results, err = AutoJoinFromEmail(ctx, r, "u2", "bob@münchen.de", true, time.Now().UTC())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(results) != 1 || results[0].OrganizationID != "org2" {
		t.Fatalf("IDNA email must autojoin org2; got %+v", results)
	}

	// A different domain must still miss (no new bypass).
	results, err = AutoJoinFromEmail(ctx, r, "u3", "mallory@evil.com.", true, time.Now().UTC())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("evil domain must not autojoin; got %+v", results)
	}
}
