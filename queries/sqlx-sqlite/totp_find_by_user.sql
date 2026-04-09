-- Find TOTP secret for a user.
-- Params: ? user_id (TEXT)
-- Returns: TOTP row or empty
-- Plugin: mfa
SELECT * FROM yauth_totp_secrets WHERE user_id = ?;
