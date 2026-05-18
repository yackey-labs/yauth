package domain

import "time"

// DomainStatus is the verification lifecycle of an OrganizationDomain
// claim. Persisted as a VARCHAR so every backend ships the column with
// no DDL drift, matching the pattern already established for
// MembershipStatus.
type DomainStatus string

const (
	// DomainPending is the state right after an admin claims a domain
	// — the verification token has been issued but the DNS TXT lookup
	// has not yet succeeded. Pending domains grant nothing.
	DomainPending DomainStatus = "pending"
	// DomainVerified means the DNS TXT lookup matched the token; the
	// domain row is now eligible for auto-join.
	DomainVerified DomainStatus = "verified"
	// DomainFailed is a terminal-for-this-attempt state set when a
	// /verify call could not find the expected TXT record. Admins can
	// retry by calling /verify again, which moves the row back through
	// pending → verified on success.
	DomainFailed DomainStatus = "failed"
)

// IsValid reports whether s is one of the three accepted values.
func (s DomainStatus) IsValid() bool {
	switch s {
	case DomainPending, DomainVerified, DomainFailed:
		return true
	default:
		return false
	}
}

// ParseDomainStatus accepts the on-disk string form and returns the
// typed status. Returns ("", false) on an unknown value.
func ParseDomainStatus(s string) (DomainStatus, bool) {
	v := DomainStatus(s)
	if !v.IsValid() {
		return "", false
	}
	return v, true
}

// OrganizationDomain is an admin-claimed email domain for an
// Organization. Port of yauth Rust #90.
//
// Verification is via a DNS TXT record at
// "_yauth-domain-verify.<domain>" whose value equals VerificationToken.
// Once verified, a domain row is eligible to act as the routing rule
// for the auto-join (JIT-membership) flow at signup + email-verify.
//
// Invariants:
//
//   - Domain is canonicalized: trimmed, lowercased.
//   - Domain is UNIQUE app-wide — one organization may claim a given
//     domain at most once across the whole deployment. This is the
//     anti-abuse gate from the spec ("'my IT bought ACME first'
//     attacks").
//   - VerificationToken is high-entropy and one-time-use per claim.
//     Rotating it requires deleting + re-creating the row.
//   - AutoJoinOnSignup defaults to false (admin opt-in).
//   - RequireEmailVerified defaults to true.
type OrganizationDomain struct {
	ID                    string
	OrganizationID        string
	Domain                string
	Status                DomainStatus
	VerificationToken     string
	VerifiedAt            *time.Time
	LastCheckedAt         *time.Time
	AutoJoinOnSignup      bool
	DefaultRoleOnAutoJoin string
	RequireEmailVerified  bool
	CreatedAt             time.Time
	UpdatedAt             time.Time
}

// NewOrganizationDomain is the create payload. CreatedAt / UpdatedAt
// default to time.Now().UTC() when zero.
type NewOrganizationDomain struct {
	ID                    string
	OrganizationID        string
	Domain                string
	Status                DomainStatus
	VerificationToken     string
	AutoJoinOnSignup      bool
	DefaultRoleOnAutoJoin string
	RequireEmailVerified  bool
	CreatedAt             time.Time
	UpdatedAt             time.Time
}

// UpdateOrganizationDomain is a partial update payload; nil fields are
// unchanged.
//
// Status / VerifiedAt / LastCheckedAt are written together by the
// verifier — callers use SetOrganizationDomainVerification on the repo
// for that atomic transition, not this struct.
type UpdateOrganizationDomain struct {
	AutoJoinOnSignup      *bool
	DefaultRoleOnAutoJoin *string
	RequireEmailVerified  *bool
	UpdatedAt             *time.Time
}
