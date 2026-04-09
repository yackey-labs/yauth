-- Find a specific passkey by ID and user.
-- Params: ? id (TEXT), ? user_id (TEXT)
-- Returns: passkey row or empty
-- Plugin: passkey
SELECT * FROM yauth_webauthn_credentials WHERE id = ? AND user_id = ?;
