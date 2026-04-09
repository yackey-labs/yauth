-- Find unused backup codes for a user.
-- Params: ? user_id (TEXT)
-- Returns: backup code rows
-- Plugin: mfa
SELECT * FROM yauth_backup_codes WHERE user_id = ? AND used = false;
