-- Delete an email verification by ID.
-- Params: $1 id (UUID)
-- Returns: nothing
-- Plugin: email-password
DELETE FROM yauth_email_verifications WHERE id = $1;
