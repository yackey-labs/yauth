-- Delete all email verifications for a user.
-- Params: $1 user_id (UUID)
-- Returns: nothing
-- Plugin: email-password
DELETE FROM yauth_email_verifications WHERE user_id = $1;
