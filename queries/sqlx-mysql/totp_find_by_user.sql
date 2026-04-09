-- Find TOTP secret for a user.
-- Params: ? user_id (CHAR(36))
-- Returns: TOTP row or empty
-- Plugin: mfa
SELECT * FROM yauth_totp_secrets WHERE user_id = ?;
