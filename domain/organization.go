package domain

import (
	"encoding/json"
	"strings"
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
	// OwnerRoleAuthorized opts this write into setting Role to
	// RoleOwnerName. See "the owner ceiling" on UpdateMembership.
	OwnerRoleAuthorized bool
}

// UpdateMembership is a partial update payload.
//
// # The owner ceiling
//
// Only two paths in yauth may put a user in the owner slot: creating an
// organization (whose creator becomes its owner) and the transfer-ownership
// endpoint. Every other path that writes a membership role — invitation
// accept, verified-domain auto-join, SSO JIT provisioning — takes that role
// from request input or from stored connection config an org admin wrote. An
// org admin could therefore mint an owner, or promote one, just by choosing
// where to type "owner": invite a colluding address as owner, set a domain's
// default_role_on_auto_join, or map an IdP group to it.
//
// The two legitimate paths set OwnerRoleAuthorized; repositories MUST refuse
// the owner role on every write that does not, returning
// yautherr.ErrOwnerProtected. The default is therefore the safe one — a new
// call site cannot silently forget the check, only the opt-in, and that fails
// loudly.
//
// This is the mint/promote ceiling. It composes with the pre-existing
// last-owner protection, which refuses to demote or remove the final owner.
type UpdateMembership struct {
	Role      *string
	Status    *MembershipStatus
	JoinedAt  **time.Time
	UpdatedAt *time.Time
	// OwnerRoleAuthorized opts this write into setting Role to RoleOwnerName.
	OwnerRoleAuthorized bool
}

// RoleOwnerName is the membership role that owns an organization. It is
// duplicated from auth.RoleOwner because domain sits below auth in the import
// graph; the two MUST stay identical (auth has a test asserting it).
const RoleOwnerName = "owner"

// IsOwnerRole reports whether role names the organization owner role.
// Surrounding whitespace is ignored, so " owner" cannot slip past a caller
// that trims before persisting.
func IsOwnerRole(role string) bool {
	return strings.TrimSpace(role) == RoleOwnerName
}

// OwnerRoleRefused reports whether this create tries to mint an owner without
// the explicit authorization flag. Repository implementations MUST consult it
// and return yautherr.ErrOwnerProtected when it is true.
func (n NewMembership) OwnerRoleRefused() bool {
	return !n.OwnerRoleAuthorized && IsOwnerRole(n.Role)
}

// OwnerRoleRefused reports whether this update tries to promote to owner
// without the explicit authorization flag. Repository implementations MUST
// consult it and return yautherr.ErrOwnerProtected when it is true.
func (u UpdateMembership) OwnerRoleRefused() bool {
	return !u.OwnerRoleAuthorized && u.Role != nil && IsOwnerRole(*u.Role)
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
