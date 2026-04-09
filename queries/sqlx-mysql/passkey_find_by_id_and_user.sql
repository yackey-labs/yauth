-- Find a specific passkey by ID and user.
-- Params: ? id (CHAR(36)), ? user_id (CHAR(36))
-- Returns: passkey row or empty
-- Plugin: passkey
SELECT * FROM yauth_webauthn_credentials WHERE id = ? AND user_id = ?;
