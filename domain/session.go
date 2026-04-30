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
