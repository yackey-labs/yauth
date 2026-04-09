-- Delete all email verifications for a user.
-- Params: ? user_id (CHAR(36))
-- Returns: nothing
-- Plugin: email-password
DELETE FROM yauth_email_verifications WHERE user_id = ?;
