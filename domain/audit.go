package domain

import "time"

// AuditLog is an append-only authentication event record.
type AuditLog struct {
	ID        string
	UserID    *string
	EventType string
	Metadata  []byte
	IPAddress *string
	CreatedAt time.Time
}

// NewAuditLog is the input for inserting an audit log entry.
type NewAuditLog struct {
	ID        string
	UserID    *string
	EventType string
	Metadata  []byte
	IPAddress *string
	CreatedAt time.Time
}

// ListAuditFilters is the filter set for AuditLogRepository.ListAuditLog.
// All fields are optional; nil pointers are treated as "no filter".
type ListAuditFilters struct {
	UserID    *string
	EventType *string
	Limit     int
	Offset    int
}
