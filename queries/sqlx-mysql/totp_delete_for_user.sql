-- Delete TOTP secrets for a user.
-- Params: ? user_id (CHAR(36))
-- Returns: nothing
-- Plugin: mfa
DELETE FROM yauth_totp_secrets WHERE user_id = ?;
