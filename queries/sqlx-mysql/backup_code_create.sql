-- Create a backup code.
-- Params: ? id (CHAR(36)), ? user_id (CHAR(36)), ? code_hash (VARCHAR(64))
-- Returns: nothing
-- Plugin: mfa
INSERT INTO yauth_backup_codes (id, user_id, code_hash, used, created_at)
VALUES (?, ?, ?, false, CURRENT_TIMESTAMP);
