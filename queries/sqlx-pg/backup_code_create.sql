-- Create a backup code.
-- Params: $1 id (UUID), $2 user_id (UUID), $3 code_hash (VARCHAR(64))
-- Returns: nothing
-- Plugin: mfa
INSERT INTO yauth_backup_codes (id, user_id, code_hash, used, created_at)
VALUES ($1, $2, $3, false, NOW());
