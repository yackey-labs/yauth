// Package auth — Verified-domain DNS verification primitive (yauth Rust
// #90 port / Go #17).
//
// This file owns the lookup half of the OrganizationDomain verification
// flow:
//
//  1. Admin claims a domain → row is created with a fresh
//     VerificationToken in status=pending (handler in
//     plugins/organizations/domains_handlers.go).
//  2. Admin sets DNS TXT _yauth-domain-verify.<domain> = <token>.
//  3. Admin (or, eventually, a background job — out of scope for the
//     initial port) POSTs /verify, which calls VerifyDomainTXT below.
//
// VerifyDomainTXT is the pure verification step — it owns the DNS
// lookup, name canonicalization, and "did any returned record match the
// expected token" check. It returns a typed result the caller maps onto
// the SetOrganizationDomainVerification repo call. The function is
// resolver-injectable so tests don't hit real DNS.
package auth

import (
	"context"
	"errors"
	"net"
	"strings"

	"golang.org/x/net/idna"
)

// DomainTXTLookupPrefix is the DNS label the verifier prepends to the
// candidate domain to form the lookup name. Matches the spec language
// "DNS TXT record at _yauth-domain-verify.<domain>".
const DomainTXTLookupPrefix = "_yauth-domain-verify"

// DomainTXTResolver is the narrow interface the verifier consumes —
// "given a name, give me the TXT records at that name". A
// production-time *net.Resolver satisfies it directly via the
// LookupTXTAdapter; tests inject a hand-rolled fake.
type DomainTXTResolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// LookupTXTAdapter wraps a *net.Resolver so it implements
// DomainTXTResolver. Pass net.DefaultResolver to use the OS resolver, or
// a custom *net.Resolver wired to a specific PreferGo / Dial config.
type LookupTXTAdapter struct {
	Resolver *net.Resolver
}

// LookupTXT implements DomainTXTResolver.
func (a LookupTXTAdapter) LookupTXT(ctx context.Context, name string) ([]string, error) {
	resolver := a.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	return resolver.LookupTXT(ctx, name)
}

// DefaultDomainTXTResolver is the resolver used when none is injected.
// Resolves via the OS default. Concurrency-safe for shared use.
var DefaultDomainTXTResolver DomainTXTResolver = LookupTXTAdapter{}

// CanonicalizeDomain normalizes a DNS domain name for comparison and
// lookup: surrounding whitespace is trimmed, a single trailing dot (the
// FQDN root marker, as in "acme.com.") is stripped, the name is
// lowercased, and non-ASCII labels are punycode-encoded via
// idna.Lookup.ToASCII ("münchen.de" → "xn--mnchen-3ya.de").
//
// The direction is fail-closed: an empty input or a name idna rejects
// returns ErrInvalidDomain, so callers treat it as "not proved" rather
// than falling back to the raw string. Comparison must always go through
// this helper on BOTH sides; a stored row written before canonicalization
// existed (raw Unicode or with a trailing dot) will not match its
// canonical form until re-saved — a miss, never a false allow.
func CanonicalizeDomain(s string) (string, error) {
	t := strings.TrimSpace(s)
	// Strip one trailing dot: the DNS root marker. "acme.com." and
	// "acme.com" name the same node. Only one is stripped — ".." is
	// not a valid name and idna will refuse what remains.
	t = strings.TrimSuffix(t, ".")
	t = strings.ToLower(t)
	if t == "" {
		return "", ErrInvalidDomain
	}
	ascii, err := idna.Lookup.ToASCII(t)
	if err != nil {
		return "", ErrInvalidDomain
	}
	// ToASCII preserves a trailing dot on FQDN input that still carried
	// one (and lowercases); normalize again defensively.
	ascii = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(ascii), "."))
	if ascii == "" {
		return "", ErrInvalidDomain
	}
	return ascii, nil
}

// VerifyDomainTXT looks up TXT records at "_yauth-domain-verify.<domain>"
// and reports whether any record exactly equals expectedToken. The match
// is exact-string against each returned TXT chunk; we do not split
// records on whitespace or attempt key=value parsing — both Auth0 and
// WorkOS use the raw-token convention.
//
// Returns (matched, nil) when the lookup succeeded and a match was (or
// was not) found. Returns (false, err) for DNS lookup errors that
// indicate the record could not be checked (network failure, NXDOMAIN
// wrapped under a *net.DNSError that's neither IsNotFound nor
// IsTemporary). NXDOMAIN / "no such host" specifically returns (false,
// nil) — it's a confirmed negative result, not an error.
//
// The function never panics. It rejects empty domains with
// ErrInvalidDomain.
func VerifyDomainTXT(ctx context.Context, resolver DomainTXTResolver, domainStr, expectedToken string) (bool, error) {
	domainStr, err := CanonicalizeDomain(domainStr)
	if err != nil {
		return false, ErrInvalidDomain
	}
	if expectedToken == "" {
		return false, ErrInvalidDomain
	}
	if resolver == nil {
		resolver = DefaultDomainTXTResolver
	}

	name := DomainTXTLookupPrefix + "." + domainStr
	records, err := resolver.LookupTXT(ctx, name)
	if err != nil {
		// NXDOMAIN is a "confirmed not present" result — treat as a
		// non-match rather than a lookup failure. We do not consider
		// that an error the caller should retry.
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return false, nil
		}
		return false, err
	}
	for _, rec := range records {
		if rec == expectedToken {
			return true, nil
		}
	}
	return false, nil
}

// ErrInvalidDomain is returned by VerifyDomainTXT when the supplied
// domain or token is empty / blank. Callers map this to 400.
var ErrInvalidDomain = errors.New("yauth: domain or verification token is empty")
