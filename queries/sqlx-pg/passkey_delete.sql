-- Delete a passkey by ID.
-- Params: $1 id (UUID)
-- Returns: nothing
-- Plugin: passkey
DELETE FROM yauth_webauthn_credentials WHERE id = $1;
