-- Find a valid, unused password reset by token hash.
-- Params: $1 token_hash (VARCHAR(64))
-- Returns: reset row or empty
-- Plugin: email-password
SELECT * FROM yauth_password_resets WHERE token_hash = $1 AND expires_at > NOW() AND used_at IS NULL;
