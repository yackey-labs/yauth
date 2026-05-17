package domain

import (
	"encoding/json"
	"time"
)

// APIKey is a long-lived bearer credential identified by prefix.
//
// An APIKey is owned by exactly one of:
//
//   - a User (the existing user-scoped key path; UserID is non-nil,
//     OrganizationID is nil), or
//   - an Organization (the service-account path added in yauth #91 /
//     yauth-go #19; OrganizationID is non-nil, UserID is nil).
//
// The "exactly one" invariant is enforced by the repository layer (and
// by a CHECK constraint in SQL backends). CreatedByUserID is the audit
// breadcrumb back to the human who minted the key — even for org-scoped
// keys whose UserID is nil.
type APIKey struct {
	ID             string
	UserID         *string // nil for org-scoped (service-account) keys
	OrganizationID *string // nil for user-scoped keys
	KeyPrefix      string
	KeyHash        string
	Name           string
	Scopes         json.RawMessage
	// Role is the org role the bearer acts as for org-scoped keys.
	// Always nil on user-scoped rows. Free-form string; the resolver
	// surfaces it on AuthUser.OrgRole when authenticating.
	Role            *string
	LastUsedAt      *time.Time
	ExpiresAt       *time.Time
	CreatedAt       time.Time
	CreatedByUserID string // human who minted the key (audit trail)
}

// NewAPIKey is the input for creating an API key.
//
// Exactly one of UserID or OrganizationID MUST be non-nil. The repo
// layer rejects rows that violate the invariant with
// yautherr.ErrInvalidArgument.
type NewAPIKey struct {
	ID              string
	UserID          *string
	OrganizationID  *string
	KeyPrefix       string
	KeyHash         string
	Name            string
	Scopes          json.RawMessage
	Role            *string
	ExpiresAt       *time.Time
	CreatedAt       time.Time
	CreatedByUserID string
}
