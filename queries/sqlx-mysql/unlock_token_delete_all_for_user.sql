-- Delete all unlock tokens for a user.
-- Params: ? user_id (CHAR(36))
-- Returns: nothing
-- Plugin: account-lockout
DELETE FROM yauth_unlock_tokens WHERE user_id = ?;
