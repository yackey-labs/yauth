-- Find all passkeys for a user.
-- Params: ? user_id (CHAR(36))
-- Returns: passkey rows
-- Plugin: passkey
SELECT * FROM yauth_webauthn_credentials WHERE user_id = ?;
