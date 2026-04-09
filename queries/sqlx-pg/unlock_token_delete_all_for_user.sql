-- Delete all unlock tokens for a user.
-- Params: $1 user_id (UUID)
-- Returns: nothing
-- Plugin: account-lockout
DELETE FROM yauth_unlock_tokens WHERE user_id = $1;
