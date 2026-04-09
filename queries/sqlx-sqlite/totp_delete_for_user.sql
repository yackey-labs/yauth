-- Delete TOTP secrets for a user.
-- Params: ? user_id (TEXT)
-- Returns: nothing
-- Plugin: mfa
DELETE FROM yauth_totp_secrets WHERE user_id = ?;
