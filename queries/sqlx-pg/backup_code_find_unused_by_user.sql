-- Find unused backup codes for a user.
-- Params: $1 user_id (UUID)
-- Returns: backup code rows
-- Plugin: mfa
SELECT * FROM yauth_backup_codes WHERE user_id = $1 AND used = false;
