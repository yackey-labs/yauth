package domain

// Auth method identifiers populated by middleware/resolvers and read by
// gates that distinguish human (cookie) from machine (bearer/api-key)
// callers. Empty string is treated as AuthMethodCookie for backwards
// compatibility with code that constructs AuthUser by hand.
const (
	AuthMethodCookie = "cookie"
	AuthMethodBearer = "bearer"
	AuthMethodAPIKey = "api-key"
)

// AuthUser is the authenticated principal injected into request context.
type AuthUser struct {
	User    User
	Session Session

	// Method records how the caller authenticated. The cookie path on
	// the middleware sets it to AuthMethodCookie; bearer/api-key
	// resolvers tag their own values. RequireAdmin can use this to
	// reject machine credentials when admin.allow_machine_callers is
	// false.
	Method string
}
