-- Delete a passkey by ID.
-- Params: ? id (CHAR(36))
-- Returns: nothing
-- Plugin: passkey
DELETE FROM yauth_webauthn_credentials WHERE id = ?;
