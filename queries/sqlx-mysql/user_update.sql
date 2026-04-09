-- Update user fields.
-- Params: ? email (VARCHAR), ? display_name (VARCHAR, nullable), ? email_verified (BOOLEAN), ? role (VARCHAR), ? banned (BOOLEAN), ? banned_reason (VARCHAR, nullable), ? banned_until (TIMESTAMPTZ, nullable), ? id (CHAR(36))
-- Returns: updated user row
-- Plugin: core
UPDATE yauth_users
SET email = ?, display_name = ?, email_verified = ?,
    role = ?, banned = ?, banned_reason = ?, banned_until = ?,
    updated_at = CURRENT_TIMESTAMP
WHERE id = ?;
