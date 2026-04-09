-- Find a valid, unused password reset by token hash.
-- Params: ? token_hash (VARCHAR(64))
-- Returns: reset row or empty
-- Plugin: email-password
SELECT * FROM yauth_password_resets WHERE token_hash = ? AND expires_at > CURRENT_TIMESTAMP AND used_at IS NULL;
