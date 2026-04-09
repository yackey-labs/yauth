-- Find a valid email verification by token hash. Expired tokens excluded.
-- Params: ? token_hash (VARCHAR(64))
-- Returns: verification row or empty
-- Plugin: email-password
SELECT * FROM yauth_email_verifications WHERE token_hash = ? AND expires_at > CURRENT_TIMESTAMP;
