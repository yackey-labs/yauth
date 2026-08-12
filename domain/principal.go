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
//
// A third dimension crosses both kinds: DELEGATION. An OAuth2 access token
// issued to a relying party resolves to the resource owner (Kind=User) but
// carries only the scope that owner consented to, so it is marked
// Delegated with the token's Audience and Scope recorded. See the field docs
// on Principal.Delegated.
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

	// Role is the org role recorded on the service-account key row (nil
	// when the key carries no role, and always nil for user principals).
	// It is the AUTHORITATIVE role for a service account: AuthUser.OrgRole
	// is a hydrated field that active-org resolution can overwrite from
	// the CREATOR's memberships, whereas this is copied straight off the
	// credential. Org authorization for a machine principal must read this
	// and the bound OrgID, never the creator's membership row — see
	// middleware.EffectiveOrgMembership.
	Role *string

	// Scopes is the explicit permission list recorded on the service-account
	// key row (domain.APIKey.Scopes, surfaced on the org API as
	// `permissions`), decoded. Nil when the key carries no list, which means
	// "bounded by Role alone" — NOT "holds no permissions".
	//
	// Like Role it is copied straight off the credential and is authoritative
	// for a machine principal. Authorization must read it through
	// auth.EffectiveKeyPermissions (or middleware.EffectiveOrgPermissions)
	// rather than testing the role in isolation: a key minted at role=viewer
	// with permissions ["members:view"] must not hold member-lifecycle
	// authority anywhere. Always nil for user principals.
	Scopes []string
	// Delegated marks a credential that was issued TO A THIRD PARTY to act
	// on the user's behalf under a limited grant — an OAuth2 access token
	// (`token_use: "access"`) whose `aud` is a relying party rather than
	// this deployment's own resource identifier.
	//
	// It is orthogonal to Kind: a delegated credential still resolves to
	// Kind=User with the resource owner's UserID, because it really does
	// speak for that person — just not with their full authority. The user
	// consented to a scope, not to the whole account.
	//
	// The zero value (false) means "the credential belongs to the caller":
	// a session cookie, a first-party bearer token from POST /token, or an
	// API key. Code that constructs a Principal by hand therefore keeps the
	// pre-delegation behaviour.
	//
	// Gate on this before doing anything that MINTS A LASTING CREDENTIAL or
	// CHANGES AN AUTHENTICATION FACTOR — see middleware.RequireUserPrincipalHuma,
	// which refuses delegated callers on exactly those routes.
	Delegated bool

	// Audience is the credential's `aud` claim, in the order it appeared.
	// Empty for cookies, API keys, and bearer tokens minted without an
	// audience. Recorded so a resource server can tell WHICH audience a
	// delegated token was issued for, and so audit trails keep the relying
	// party's identity.
	Audience []string

	// Scope is the OAuth2 scope the credential carries, split on spaces.
	// Empty for every non-OAuth2 credential (cookie, API key, first-party
	// bearer token) — an empty Scope on a non-Delegated principal means
	// "unrestricted", NOT "no permissions". Consult it only in combination
	// with Delegated, or via HasScope.
	Scope []string
}

// IsUser reports whether p is a human user principal.
func (p Principal) IsUser() bool { return p.Kind == PrincipalKindUser }

// IsServiceAccount reports whether p is an org-scoped service account.
func (p Principal) IsServiceAccount() bool { return p.Kind == PrincipalKindServiceAccount }

// IsDelegated reports whether p was resolved from a credential issued to a
// third party under a limited grant (see Principal.Delegated).
func (p Principal) IsDelegated() bool { return p.Delegated }

// HasScope reports whether the credential carries scope s.
//
// A NON-delegated credential (cookie, API key, first-party bearer token) is
// unrestricted and therefore satisfies every scope — it is the user acting
// directly, and no consent screen ever narrowed it. A delegated credential
// satisfies s only when s is in the granted set.
func (p Principal) HasScope(s string) bool {
	if !p.Delegated {
		return true
	}
	for _, got := range p.Scope {
		if got == s {
			return true
		}
	}
	return false
}

// NewUserPrincipal constructs a User principal for the given user id.
func NewUserPrincipal(userID string) Principal {
	return Principal{Kind: PrincipalKindUser, UserID: &userID}
}

// NewDelegatedUserPrincipal constructs a User principal for a credential that
// a third party holds on the user's behalf: audience is the token's `aud`,
// scope the granted scope. See Principal.Delegated.
func NewDelegatedUserPrincipal(userID string, audience, scope []string) Principal {
	p := NewUserPrincipal(userID)
	p.Delegated = true
	p.Audience = audience
	p.Scope = scope
	return p
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
