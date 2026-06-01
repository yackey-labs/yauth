package domain

import "time"

// Group is a named, organization-scoped collection of users — the yauth-go
// equivalent of an Okta group or a SCIM Group resource. Name maps to the SCIM
// "displayName"; ExternalID maps to the SCIM "externalId" (set when the group
// is provisioned by an upstream IdP). Groups are independent of the org role
// (owner/admin/member): roles govern administration, groups model access.
type Group struct {
	ID             string
	OrganizationID string
	Name           string
	Description    *string
	ExternalID     *string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// NewGroup is the input for creating a group.
type NewGroup struct {
	ID             string
	OrganizationID string
	Name           string
	Description    *string
	ExternalID     *string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// UpdateGroup carries the mutable fields of a group. Nil fields are left
// unchanged.
type UpdateGroup struct {
	Name        *string
	Description *string
	ExternalID  *string
}

// GroupMember is a single user's membership in a group.
type GroupMember struct {
	GroupID   string
	UserID    string
	CreatedAt time.Time
}

// ClientGroupAssignment links an OAuth2 client to a group that may access it
// (Okta "application group assignment"). The group implies its organization.
type ClientGroupAssignment struct {
	ClientID  string
	GroupID   string
	CreatedAt time.Time
}

// ClientRoleAssignment grants a free-form app role on a client to one
// principal — either a group (every member inherits it) or an individual user
// (Keycloak-style "client roles"). Resolved per (client, user) and emitted as
// the per-app "roles" claim.
type ClientRoleAssignment struct {
	ID        string
	ClientID  string
	Role      string
	GroupID   *string
	UserID    *string
	CreatedAt time.Time
}

// NewClientRoleAssignment is the input for assigning an app role. Exactly one
// of GroupID / UserID must be set.
type NewClientRoleAssignment struct {
	ID        string
	ClientID  string
	Role      string
	GroupID   *string
	UserID    *string
	CreatedAt time.Time
}
