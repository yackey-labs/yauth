-- Mark a backup code as used.
-- Params: ? id (CHAR(36))
-- Returns: nothing
-- Plugin: mfa
UPDATE yauth_backup_codes SET used = true WHERE id = ?;
