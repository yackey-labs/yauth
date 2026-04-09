-- Find a non-expired API key by prefix.
-- Params: ? key_prefix (VARCHAR(12))
-- Returns: API key row or empty
-- Plugin: api-key
SELECT * FROM yauth_api_keys WHERE key_prefix = ? AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP);
