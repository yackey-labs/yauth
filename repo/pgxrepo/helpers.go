package pgxrepo

import (
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/yackey-labs/yauth/yautherr"
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

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}
