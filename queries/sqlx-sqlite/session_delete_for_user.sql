-- Delete all sessions for a user.
-- Params: ? user_id (TEXT)
-- Returns: nothing
-- Plugin: core
DELETE FROM yauth_sessions WHERE user_id = ?;
