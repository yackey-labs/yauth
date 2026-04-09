-- Delete all sessions for a user except the specified one.
-- Params: ? user_id (TEXT), ? keep_token_hash (VARCHAR(64))
-- Returns: nothing
-- Plugin: core
DELETE FROM yauth_sessions WHERE user_id = ? AND token_hash != ?;
