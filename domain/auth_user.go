package domain

// AuthUser is the authenticated principal injected into request context.
type AuthUser struct {
	User    User
	Session Session
}
