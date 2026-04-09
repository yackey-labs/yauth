-- Create a password reset token.
-- Params: $1 id (UUID), $2 user_id (UUID), $3 token_hash (VARCHAR(64)), $4 expires_at (TIMESTAMPTZ)
-- Returns: nothing
-- Plugin: email-password
INSERT INTO yauth_password_resets (id, user_id, token_hash, expires_at, created_at)
VALUES ($1, $2, $3, $4, NOW());
