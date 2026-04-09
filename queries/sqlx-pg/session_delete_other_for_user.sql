-- Delete all sessions for a user except the specified one.
-- Params: $1 user_id (UUID), $2 keep_token_hash (VARCHAR(64))
-- Returns: nothing
-- Plugin: core
DELETE FROM yauth_sessions WHERE user_id = $1 AND token_hash != $2;
