-- Update user fields.
-- Params: $1 email (VARCHAR), $2 display_name (VARCHAR, nullable), $3 email_verified (BOOLEAN), $4 role (VARCHAR), $5 banned (BOOLEAN), $6 banned_reason (VARCHAR, nullable), $7 banned_until (TIMESTAMPTZ, nullable), $8 id (UUID)
-- Returns: updated user row
-- Plugin: core
UPDATE yauth_users
SET email = $1, display_name = $2, email_verified = $3,
    role = $4, banned = $5, banned_reason = $6, banned_until = $7,
    updated_at = NOW()
WHERE id = $8
RETURNING *;
