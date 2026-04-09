-- Find a valid email verification by token hash. Expired tokens excluded.
-- Params: $1 token_hash (VARCHAR(64))
-- Returns: verification row or empty
-- Plugin: email-password
SELECT * FROM yauth_email_verifications WHERE token_hash = $1 AND expires_at > NOW();
