-- Delete all unused password resets for a user.
-- Params: ? user_id (CHAR(36))
-- Returns: nothing
-- Plugin: email-password
DELETE FROM yauth_password_resets WHERE user_id = ? AND used_at IS NULL;
