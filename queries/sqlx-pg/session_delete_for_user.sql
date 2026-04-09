-- Delete all sessions for a user.
-- Params: $1 user_id (UUID)
-- Returns: nothing
-- Plugin: core
DELETE FROM yauth_sessions WHERE user_id = $1;
