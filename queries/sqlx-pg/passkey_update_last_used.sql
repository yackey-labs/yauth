-- Update last_used_at timestamp on a passkey.
-- Params: $1 user_id (UUID)
-- Returns: nothing
-- Plugin: passkey
UPDATE yauth_webauthn_credentials SET last_used_at = NOW() WHERE user_id = $1;
