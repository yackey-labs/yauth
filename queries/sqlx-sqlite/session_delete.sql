-- Delete a session by token hash.
-- Params: ? token_hash (VARCHAR(64))
-- Returns: nothing
-- Plugin: core
DELETE FROM yauth_sessions WHERE token_hash = ?;
