-- Delete an email verification by ID.
-- Params: ? id (TEXT)
-- Returns: nothing
-- Plugin: email-password
DELETE FROM yauth_email_verifications WHERE id = ?;
