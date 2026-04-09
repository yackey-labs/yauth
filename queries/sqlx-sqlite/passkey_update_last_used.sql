-- Update last_used_at timestamp on a passkey.
-- Params: ? user_id (TEXT)
-- Returns: nothing
-- Plugin: passkey
UPDATE yauth_webauthn_credentials SET last_used_at = datetime('now') WHERE user_id = ?;
