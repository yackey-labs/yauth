-- Update last_used_at timestamp on a passkey.
-- Params: ? user_id (CHAR(36))
-- Returns: nothing
-- Plugin: passkey
UPDATE yauth_webauthn_credentials SET last_used_at = CURRENT_TIMESTAMP WHERE user_id = ?;
