package domain

// Auth method identifiers populated by middleware/resolvers and read by
// gates that distinguish human (cookie) from machine (bearer/api-key)
// callers. Empty string is treated as AuthMethodCookie for backwards
// compatibility with code that constructs AuthUser by hand.
const (
	AuthMethodCookie = "cookie"
	AuthMethodBearer = "bearer"
	AuthMethodAPIKey = "api-key"
	// AuthMethodServiceAccount tags a request authenticated via an
	// org-scoped API key (yauth #91 / yauth-go #19). The credential
	// format is identical to AuthMethodAPIKey but the resolved
	// principal is a ServiceAccount; the distinct method string lets
	// admin/permission gates reject org-key callers explicitly. Note
	// that middleware.ResolveAdmin refuses a ServiceAccount principal
	// unconditionally — allow_machine_callers does not reach it.
	AuthMethodServiceAccount = "service-account"
)

// OrgMembershipSummary is a compact, JSON-safe view of an org the
// authenticated user belongs to. It is the per-org slice carried in
// AuthUser.AllOrgs and surfaced on the active-org switcher response.
//
// yauth Rust issue #89 / Go issue #15.
type OrgMembershipSummary struct {
	OrganizationID string `json:"organization_id"`
	Slug           string `json:"slug"`
	Name           string `json:"name"`
	Role           string `json:"role"`
}

// AuthUser is the authenticated principal injected into request context.
type AuthUser struct {
	// User is the fully-resolved user row. It carries MustChangePassword,
	// so middleware-resolved callers can be gated/redirected by the
	// consuming app (yauth surfaces the flag but does not block); the flag
	// is cleared automatically when the user changes or resets their
	// password. See domain.User.MustChangePassword.
	User    User
	Session Session

	// Method records how the caller authenticated. The cookie path on
	// the middleware sets it to AuthMethodCookie; bearer/api-key
	// resolvers tag their own values. RequireAdmin can use this to
	// reject machine credentials when admin.allow_machine_callers is
	// false.
	Method string

	// ActiveOrgID mirrors Session.ActiveOrgID (cookie path) or the
	// JWT "org" claim (bearer path) for ergonomic access in handlers.
	// nil when the user has no active org — single-user deployments,
	// users with zero memberships, or deployments without the
	// organizations plugin. yauth #89 / Go #15.
	ActiveOrgID *string

	// OrgRole is the caller's role in ActiveOrgID. nil iff ActiveOrgID
	// is nil. Free-form string — built-in or app-defined.
	OrgRole *string

	// AllOrgs is every org the user is a member of, in deterministic
	// order (by name). Empty slice when the user has no memberships
	// or the organizations plugin isn't loaded. Bounded by membership
	// cardinality (small in practice).
	AllOrgs []OrgMembershipSummary

	// Principal is the post-authentication identity discriminator
	// (yauth #91 / yauth-go #19). For human-callers (cookie, bearer
	// JWT, user-scoped API key) it carries Kind=User and UserID
	// matches User.ID. For service-account callers (org-scoped API
	// key) it carries Kind=ServiceAccount with OrgID/KeyID/CreatedBy
	// populated and User.ID synthesised from CreatedBy so existing
	// audit code that reads User.ID still receives a useful value.
	//
	// The zero Principal (Kind == "") is treated as a User principal
	// for backwards compatibility with handlers that build AuthUser
	// by hand without setting this field.
	Principal Principal
}
