package pgxrepo

import (
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/yackey-labs/yauth-go/yautherr"
)

// ts converts a time.Time to pgtype.Timestamptz.
func ts(t time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: t.UTC(), Valid: true}
}

// tsPtr converts a *time.Time to pgtype.Timestamptz (invalid when nil).
func tsPtr(t *time.Time) pgtype.Timestamptz {
	if t == nil {
		return pgtype.Timestamptz{}
	}
	return pgtype.Timestamptz{Time: t.UTC(), Valid: true}
}

// fromTS converts pgtype.Timestamptz to time.Time (zero if invalid).
func fromTS(t pgtype.Timestamptz) time.Time {
	if !t.Valid {
		return time.Time{}
	}
	return t.Time.UTC()
}

// fromTSPtr converts pgtype.Timestamptz to *time.Time (nil if invalid).
func fromTSPtr(t pgtype.Timestamptz) *time.Time {
	if !t.Valid {
		return nil
	}
	u := t.Time.UTC()
	return &u
}

// notFound returns yautherr.ErrNotFound when err is pgx.ErrNoRows, else err.
func notFound(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return yautherr.ErrNotFound
	}
	return err
}

// notFoundOr wraps notFound but returns the sentinel when err is ErrNoRows.
func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "23505") ||
		strings.Contains(msg, "unique constraint") ||
		strings.Contains(msg, "duplicate key")
}

// ptrStr dereferences a *string safely.
func ptrStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func strPtr(s string) *string { return &s }

func boolPtr(b bool) *bool { return &b }
