package domain

import "time"

// Session is a persisted login session.
type Session struct {
	ID        string
	UserID    string
	TokenHash string
	IPAddress *string
	UserAgent *string
	ExpiresAt time.Time
	CreatedAt time.Time
}

// NewSession is the input for creating a session.
type NewSession struct {
	ID        string
	UserID    string
	TokenHash string
	IPAddress *string
	UserAgent *string
	ExpiresAt time.Time
	CreatedAt time.Time
}

// ListSessionsFilters is the filter set for SessionRepository.ListSessions.
// All fields are optional; nil pointers and zero values are treated as
// "no filter".
type ListSessionsFilters struct {
	UserID *string
	Limit  int
	Offset int
}
