-- Update user fields.
-- Params: ? email (VARCHAR), ? display_name (VARCHAR, nullable), ? email_verified (BOOLEAN), ? role (VARCHAR), ? banned (BOOLEAN), ? banned_reason (VARCHAR, nullable), ? banned_until (TIMESTAMPTZ, nullable), ? id (TEXT)
-- Returns: updated user row
-- Plugin: core
UPDATE yauth_users
SET email = ?, display_name = ?, email_verified = ?,
    role = ?, banned = ?, banned_reason = ?, banned_until = ?,
    updated_at = datetime('now')
WHERE id = ?
RETURNING *;
