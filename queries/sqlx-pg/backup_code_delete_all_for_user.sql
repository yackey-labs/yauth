-- Delete all backup codes for a user.
-- Params: $1 user_id (UUID)
-- Returns: nothing
-- Plugin: mfa
DELETE FROM yauth_backup_codes WHERE user_id = $1;
