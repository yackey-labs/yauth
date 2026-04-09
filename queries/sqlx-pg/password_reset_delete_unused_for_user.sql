-- Delete all unused password resets for a user.
-- Params: $1 user_id (UUID)
-- Returns: nothing
-- Plugin: email-password
DELETE FROM yauth_password_resets WHERE user_id = $1 AND used_at IS NULL;
