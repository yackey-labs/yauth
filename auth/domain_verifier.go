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
	domainStr = strings.ToLower(strings.TrimSpace(domainStr))
	if domainStr == "" {
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
