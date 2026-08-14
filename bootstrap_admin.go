package yauth

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth/auth"
	"github.com/yackey-labs/yauth/auth/passwordpolicy"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/repo"
	"github.com/yackey-labs/yauth/yauthcfg"
	"github.com/yackey-labs/yauth/yautherr"
)

// bootstrapAdmin deterministically provisions the first administrator on
// startup. It is the secure default for seeding an admin (over
// auto_admin_first_user, which promotes whoever registers first publicly).
//
// Behaviour, given bootstrap_admin is enabled:
//
//   - If an admin already exists, do nothing (fast path; no write, no log).
//   - Otherwise attempt to create the admin user (role "admin",
//     must_change_password=true) + password in a single, idempotent step.
//   - The bootstrap password is the operator-provided one if set (NEVER
//     logged), or a strong random password satisfying the configured policy,
//     logged EXACTLY ONCE at WARN at creation.
//
// Idempotency + multi-replica safety: creation relies on the yauth_users email
// unique constraint (CreateUser returns yautherr.ErrUserExists on conflict —
// equivalent to INSERT … ON CONFLICT (email) DO NOTHING). The random password
// is generated, and the one-time WARN emitted, ONLY when CreateUser actually
// inserts a row. Two replicas racing, or any restart, therefore never create a
// duplicate admin nor re-log the password — the loser of the race sees
// ErrUserExists and returns silently.
//
// Failure policy: every error is logged and swallowed (never panics, never
// fails process start). The schema is assumed to exist (consumers run
// `yauth migrate` before serve); a missing-table error is logged like any
// other and start proceeds.
func bootstrapAdmin(ctx context.Context, r repo.Repository, logger *slog.Logger, cfg yauthcfg.BootstrapAdminConfig, policy passwordpolicy.Policy) {
	if logger == nil {
		logger = slog.Default()
	}
	email := strings.TrimSpace(strings.ToLower(cfg.Email))
	if email == "" {
		// Validate() already rejects this when enabled; guard defensively so a
		// builder-path caller can't blank-provision.
		logger.Warn("yauth: bootstrap_admin enabled but email is empty — skipping")
		return
	}

	// Fast path / race short-circuit: if any admin already exists, do nothing.
	// This also covers the steady-state restart case (admin created on a
	// previous boot) without touching the row or its password.
	if exists, err := anAdminExists(ctx, r); err != nil {
		logger.Warn("yauth: bootstrap admin check failed — skipping provisioning", "err", err)
		return
	} else if exists {
		return
	}

	// Resolve the password BEFORE the insert so we know whether a generated
	// one would need logging. Whether it is operator-provided or generated, we
	// only log (and only ever the generated one) after a successful INSERT.
	password := cfg.Password
	generated := false
	if password == "" {
		pw, err := passwordpolicy.Generate(policy)
		if err != nil {
			logger.Warn("yauth: bootstrap admin password generation failed — skipping", "err", err)
			return
		}
		password = pw
		generated = true
	}

	hash, err := auth.HashPassword(password)
	if err != nil {
		logger.Warn("yauth: bootstrap admin password hashing failed — skipping", "err", err)
		return
	}

	now := time.Now().UTC()
	user, err := r.CreateUser(ctx, domain.NewUser{
		ID:                 uuid.NewString(),
		Email:              email,
		Role:               "admin",
		EmailVerified:      true,
		MustChangePassword: true,
		CreatedAt:          now,
		UpdatedAt:          now,
	})
	if err != nil {
		if errors.Is(err, yautherr.ErrUserExists) {
			// Another replica won the race (or a non-admin user already holds
			// this email). Either way we did NOT insert, so we never log the
			// password. Idempotent no-op.
			return
		}
		logger.Warn("yauth: bootstrap admin create failed — skipping (run `yauth migrate` first if the schema is missing)", "err", err)
		return
	}

	// The row is ours: persist the password BEFORE logging so we never emit a
	// password the user cannot log in with. If storing the password fails the
	// admin row exists but is unusable — surface it loudly and tell the
	// operator how to recover. Do NOT log the password in that case.
	if err := r.UpsertPassword(ctx, domain.NewPassword{
		UserID:       user.ID,
		PasswordHash: hash,
	}); err != nil {
		logger.Error("yauth: bootstrap admin provisioned but storing its password failed — the admin row exists without a usable password; delete the user row and restart to re-provision",
			"email", email, "user_id", user.ID, "err", err)
		return
	}

	if generated {
		// The one-time, intended secret disclosure. Operator-provided passwords
		// are NEVER logged.
		logger.Warn("yauth: bootstrap admin provisioned — log in and change the password immediately",
			"email", email, "password", password)
	} else {
		logger.Warn("yauth: bootstrap admin provisioned with the operator-provided password — log in and change it immediately",
			"email", email)
	}
}

// anAdminExists reports whether at least one user with role "admin" exists. It
// pages through ListUsers (no dedicated count exists on the Repository
// interface) and returns true on the first admin found. The admin set is tiny
// in practice, so the page size is generous and the scan terminates early.
func anAdminExists(ctx context.Context, r repo.Repository) (bool, error) {
	const page = 200
	offset := 0
	for {
		users, total, err := r.ListUsers(ctx, "", page, offset)
		if err != nil {
			return false, err
		}
		for _, u := range users {
			if u != nil && u.Role == "admin" {
				return true, nil
			}
		}
		offset += len(users)
		if len(users) == 0 || int64(offset) >= total {
			return false, nil
		}
	}
}
