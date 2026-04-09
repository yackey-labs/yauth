-- Mark a backup code as used.
-- Params: $1 id (UUID)
-- Returns: nothing
-- Plugin: mfa
UPDATE yauth_backup_codes SET used = true WHERE id = $1;
