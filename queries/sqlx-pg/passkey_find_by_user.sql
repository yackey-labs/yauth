-- Find all passkeys for a user.
-- Params: $1 user_id (UUID)
-- Returns: passkey rows
-- Plugin: passkey
SELECT * FROM yauth_webauthn_credentials WHERE user_id = $1;
