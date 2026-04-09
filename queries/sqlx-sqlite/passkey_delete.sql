-- Delete a passkey by ID.
-- Params: ? id (TEXT)
-- Returns: nothing
-- Plugin: passkey
DELETE FROM yauth_webauthn_credentials WHERE id = ?;
