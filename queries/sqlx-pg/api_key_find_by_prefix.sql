-- Find a non-expired API key by prefix.
-- Params: $1 key_prefix (VARCHAR(12))
-- Returns: API key row or empty
-- Plugin: api-key
SELECT * FROM yauth_api_keys WHERE key_prefix = $1 AND (expires_at IS NULL OR expires_at > NOW());
