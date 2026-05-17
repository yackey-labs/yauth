package auth

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
)

// fakeTXTResolver implements DomainTXTResolver against a hand-built map.
// Each test wires the exact name → records mapping it needs; absent keys
// surface as NXDOMAIN-equivalent IsNotFound DNSError.
type fakeTXTResolver struct {
	records map[string][]string
	err     error
}

func (f *fakeTXTResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	if f.err != nil {
		return nil, f.err
	}
	v, ok := f.records[name]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}
	return v, nil
}

func TestVerifyDomainTXT_Match(t *testing.T) {
	r := &fakeTXTResolver{records: map[string][]string{
		"_yauth-domain-verify.acme.com": {"unrelated", "yauth-verify=secret-token"},
	}}
	ok, err := VerifyDomainTXT(context.Background(), r, "acme.com", "yauth-verify=secret-token")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !ok {
		t.Fatalf("expected match")
	}
}

func TestVerifyDomainTXT_NoMatchAmongMultiple(t *testing.T) {
	r := &fakeTXTResolver{records: map[string][]string{
		"_yauth-domain-verify.acme.com": {"v=spf1 -all", "google-site-verification=other"},
	}}
	ok, err := VerifyDomainTXT(context.Background(), r, "acme.com", "yauth-verify=secret-token")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if ok {
		t.Fatalf("expected no match")
	}
}

func TestVerifyDomainTXT_NXDOMAINTreatedAsNonMatch(t *testing.T) {
	r := &fakeTXTResolver{records: map[string][]string{}}
	ok, err := VerifyDomainTXT(context.Background(), r, "missing.example", "yauth-verify=x")
	if err != nil {
		t.Fatalf("NXDOMAIN should not propagate as error; got %v", err)
	}
	if ok {
		t.Fatalf("expected no match")
	}
}

func TestVerifyDomainTXT_NetworkErrorPropagates(t *testing.T) {
	wantErr := errors.New("connection refused")
	r := &fakeTXTResolver{err: wantErr}
	ok, err := VerifyDomainTXT(context.Background(), r, "acme.com", "yauth-verify=x")
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected wrapped err to propagate; got %v", err)
	}
	if ok {
		t.Fatalf("expected no match on error")
	}
}

func TestVerifyDomainTXT_CanonicalizesDomain(t *testing.T) {
	// Mixed-case input should still hit the lowercase lookup name.
	r := &fakeTXTResolver{records: map[string][]string{
		"_yauth-domain-verify.acme.com": {"yauth-verify=t"},
	}}
	ok, err := VerifyDomainTXT(context.Background(), r, "  ACME.com  ", "yauth-verify=t")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !ok {
		t.Fatalf("expected canonicalized lookup to match")
	}
}

func TestVerifyDomainTXT_EmptyInputsRejected(t *testing.T) {
	cases := []struct{ domain, token string }{
		{"", "tok"},
		{"acme.com", ""},
		{"   ", "tok"},
	}
	r := &fakeTXTResolver{}
	for _, c := range cases {
		t.Run(fmt.Sprintf("%q/%q", c.domain, c.token), func(t *testing.T) {
			_, err := VerifyDomainTXT(context.Background(), r, c.domain, c.token)
			if !errors.Is(err, ErrInvalidDomain) {
				t.Fatalf("expected ErrInvalidDomain; got %v", err)
			}
		})
	}
}

func TestVerifyDomainTXT_NilResolverFallsBackToDefault(t *testing.T) {
	// We can't reach real DNS in CI; assert only that nil resolver
	// doesn't panic. Use an obviously-NXDOMAIN host so the OS
	// resolver returns the IsNotFound path quickly.
	_, err := VerifyDomainTXT(context.Background(), nil, "this-domain-must-not-exist.invalid", "yauth-verify=x")
	// Either a NotFound (clean nil err) or a network-level error —
	// both are acceptable; the test exists only to assert no panic.
	_ = err
}
