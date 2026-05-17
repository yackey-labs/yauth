// Package domain — Principal (yauth Rust #91 / yauth-go #19 port).
//
// A Principal is the post-authentication identity attached to a request.
// It exists alongside AuthUser to give downstream code a single value
// that explicitly distinguishes a human caller from a service-account
// caller, without having to reach into AuthUser.Method and the various
// nullable fields.
//
// User-scoped flows (password, magic link, passkey, bearer JWT carrying
// `sub`, user-scoped API key) yield Principal{Kind: PrincipalKindUser,
// UserID: &uid}.
//
// Org-scoped API keys (yauth #91) yield Principal{Kind:
// PrincipalKindServiceAccount, OrgID: &org, KeyID: &kid, CreatedBy:
// &uid}.  UserID is always nil for service accounts; the human who
// minted the key is on CreatedBy for audit.
package domain

// PrincipalKind discriminates User vs ServiceAccount callers.
type PrincipalKind string

const (
	// PrincipalKindUser is a human caller — any auth method that
	// resolves to a single User row (cookie, bearer JWT, user-scoped
	// API key).
	PrincipalKindUser PrincipalKind = "user"

	// PrincipalKindServiceAccount is an org-scoped API key (yauth
	// #91 / #19). No human user is logged in; the bearer acts as
	// the organization in the role recorded on the key.
	PrincipalKindServiceAccount PrincipalKind = "service_account"
)

// Principal is the authenticated identity for a request.
//
// Invariants per Kind:
//
//   - User: UserID is non-nil; OrgID/KeyID/CreatedBy are nil.
//   - ServiceAccount: OrgID, KeyID, and CreatedBy are non-nil; UserID
//     is nil.
//
// The zero value is invalid (Kind == ""); callers should never see a
// zero Principal.
type Principal struct {
	Kind PrincipalKind

	// UserID is the human user's id for PrincipalKindUser; nil for
	// service accounts.
	UserID *string

	// OrgID is the owning organization for service-account callers;
	// nil for user principals.
	OrgID *string

	// KeyID is the API key row id for service-account callers; nil
	// for user principals. Used by audit logs to trail back to the
	// specific credential.
	KeyID *string

	// CreatedBy is the user id of the human who minted the
	// service-account key; nil for user principals. Audit log column
	// — `KeyID + CreatedBy` retains the human breadcrumb on every
	// service-account call.
	CreatedBy *string
}

// IsUser reports whether p is a human user principal.
func (p Principal) IsUser() bool { return p.Kind == PrincipalKindUser }

// IsServiceAccount reports whether p is an org-scoped service account.
func (p Principal) IsServiceAccount() bool { return p.Kind == PrincipalKindServiceAccount }

// NewUserPrincipal constructs a User principal for the given user id.
func NewUserPrincipal(userID string) Principal {
	return Principal{Kind: PrincipalKindUser, UserID: &userID}
}

// NewServiceAccountPrincipal constructs a ServiceAccount principal.
func NewServiceAccountPrincipal(orgID, keyID, createdByUserID string) Principal {
	return Principal{
		Kind:      PrincipalKindServiceAccount,
		OrgID:     &orgID,
		KeyID:     &keyID,
		CreatedBy: &createdByUserID,
	}
}
