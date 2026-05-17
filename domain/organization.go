package domain

import (
	"encoding/json"
	"time"
)

// MembershipStatus is the lifecycle state of a Membership row. It is
// persisted as a VARCHAR (or TEXT) column with one of the three values
// below so every backend can ship the column with no DDL drift.
type MembershipStatus string

const (
	// MembershipActive means the invitation was accepted; the user is
	// a full member.
	MembershipActive MembershipStatus = "active"
	// MembershipInvited is a convenience listing on the org page. The
	// canonical pending record lives in Invitation.
	MembershipInvited MembershipStatus = "invited"
	// MembershipSuspended keeps a member row for audit/history while
	// blocking them from acting on the org.
	MembershipSuspended MembershipStatus = "suspended"
)

// IsValid reports whether s is one of the three accepted values.
func (s MembershipStatus) IsValid() bool {
	switch s {
	case MembershipActive, MembershipInvited, MembershipSuspended:
		return true
	default:
		return false
	}
}

// ParseMembershipStatus accepts the on-disk string form and returns the
// typed status. Returns (status, true) on success or ("", false) on an
// unknown value.
func ParseMembershipStatus(s string) (MembershipStatus, bool) {
	v := MembershipStatus(s)
	if !v.IsValid() {
		return "", false
	}
	return v, true
}

// Organization is the multi-tenant boundary. Users join via Membership.
//
// See yauth (Rust) PR #98 / issue #87 for the shape rationale — the
// fields mirror Better Auth / WorkOS / Stytch conventions so downstream
// callers can swap in.
type Organization struct {
	ID   string
	Name string
	// Slug is the URL-safe identifier, globally unique on a
	// case-insensitive basis.
	Slug        string
	DisplayName *string
	AvatarURL   *string
	// Metadata is free-form JSON for callers — billing IDs, SAML
	// config, etc. Empty bytes means no metadata.
	Metadata  json.RawMessage
	CreatedAt time.Time
	UpdatedAt time.Time
}

// NewOrganization is the create payload.
type NewOrganization struct {
	ID          string
	Name        string
	Slug        string
	DisplayName *string
	AvatarURL   *string
	Metadata    json.RawMessage
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// UpdateOrganization is a partial update payload; nil fields are
// unchanged. Double-pointer fields let callers explicitly clear
// nullable columns.
type UpdateOrganization struct {
	Name        *string
	Slug        *string
	DisplayName **string
	AvatarURL   **string
	// Metadata is a triple-state pointer: nil = leave unchanged;
	// pointer to nil RawMessage = clear; pointer to non-nil = replace.
	Metadata  *json.RawMessage
	UpdatedAt *time.Time
}

// Membership ties a User to an Organization with a per-org role.
//
// Roles are free-form strings — RBAC enforcement is a separate plugin
// (Rust issue #88, deferred for Go) and intentionally not gated here.
type Membership struct {
	ID             string
	OrganizationID string
	UserID         string
	Role           string
	Status         MembershipStatus
	InvitedAt      *time.Time
	JoinedAt       *time.Time
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// NewMembership is the create payload.
type NewMembership struct {
	ID             string
	OrganizationID string
	UserID         string
	Role           string
	Status         MembershipStatus
	InvitedAt      *time.Time
	JoinedAt       *time.Time
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// UpdateMembership is a partial update payload.
type UpdateMembership struct {
	Role      *string
	Status    *MembershipStatus
	JoinedAt  **time.Time
	UpdatedAt *time.Time
}

// Invitation is a pending invite to join an organization.
//
// TokenHash stores a hashed representation of the token; the plaintext
// is only returned at creation and delivered out-of-band (email).
// Single-use semantics are enforced by AcceptedAt combined with
// ExpiresAt.
type Invitation struct {
	ID              string
	OrganizationID  string
	Email           string
	Role            string
	TokenHash       string
	InvitedByUserID string
	ExpiresAt       time.Time
	AcceptedAt      *time.Time
	CreatedAt       time.Time
}

// NewInvitation is the create payload.
type NewInvitation struct {
	ID              string
	OrganizationID  string
	Email           string
	Role            string
	TokenHash       string
	InvitedByUserID string
	ExpiresAt       time.Time
	AcceptedAt      *time.Time
	CreatedAt       time.Time
}
