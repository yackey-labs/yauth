-- Delete all sessions for a user.
-- Params: ? user_id (CHAR(36))
-- Returns: nothing
-- Plugin: core
DELETE FROM yauth_sessions WHERE user_id = ?;
