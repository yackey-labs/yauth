package domain

import "time"

// Session is a persisted login session.
type Session struct {
	ID        string
	UserID    string
	TokenHash string
	IPAddress *string
	UserAgent *string
	// ActiveOrgID is the organization the session is currently
	// operating under. nil means "no active org" — either the user
	// has no memberships, or the deployment isn't using the
	// organizations plugin. yauth Rust issue #89 / Go issue #15.
	ActiveOrgID *string
	ExpiresAt   time.Time
	CreatedAt   time.Time
}

// NewSession is the input for creating a session.
type NewSession struct {
	ID          string
	UserID      string
	TokenHash   string
	IPAddress   *string
	UserAgent   *string
	ActiveOrgID *string
	ExpiresAt   time.Time
	CreatedAt   time.Time
}

// ListSessionsFilters is the filter set for SessionRepository.ListSessions.
// All fields are optional; nil pointers and zero values are treated as
// "no filter".
type ListSessionsFilters struct {
	UserID *string
	Limit  int
	Offset int
}
