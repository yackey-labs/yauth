-- Find TOTP secret for a user.
-- Params: $1 user_id (UUID)
-- Returns: TOTP row or empty
-- Plugin: mfa
SELECT * FROM yauth_totp_secrets WHERE user_id = $1;
