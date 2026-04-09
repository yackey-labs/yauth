-- Create a password reset token.
-- Params: ? id (CHAR(36)), ? user_id (CHAR(36)), ? token_hash (VARCHAR(64)), ? expires_at (TIMESTAMPTZ)
-- Returns: nothing
-- Plugin: email-password
INSERT INTO yauth_password_resets (id, user_id, token_hash, expires_at, created_at)
VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP);
