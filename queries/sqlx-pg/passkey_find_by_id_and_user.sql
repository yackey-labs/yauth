-- Find a specific passkey by ID and user.
-- Params: $1 id (UUID), $2 user_id (UUID)
-- Returns: passkey row or empty
-- Plugin: passkey
SELECT * FROM yauth_webauthn_credentials WHERE id = $1 AND user_id = $2;
