-- Delete all backup codes for a user.
-- Params: ? user_id (CHAR(36))
-- Returns: nothing
-- Plugin: mfa
DELETE FROM yauth_backup_codes WHERE user_id = ?;
