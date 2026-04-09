-- Find all passkeys for a user.
-- Params: ? user_id (TEXT)
-- Returns: passkey rows
-- Plugin: passkey
SELECT * FROM yauth_webauthn_credentials WHERE user_id = ?;
