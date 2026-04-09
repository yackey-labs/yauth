-- Delete a session by token hash.
-- Params: $1 token_hash (VARCHAR(64))
-- Returns: nothing
-- Plugin: core
DELETE FROM yauth_sessions WHERE token_hash = $1;
