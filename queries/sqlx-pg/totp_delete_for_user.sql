-- Delete TOTP secrets for a user.
-- Params: $1 user_id (UUID)
-- Returns: nothing
-- Plugin: mfa
DELETE FROM yauth_totp_secrets WHERE user_id = $1;
