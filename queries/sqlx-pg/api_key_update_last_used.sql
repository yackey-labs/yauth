-- Update last_used_at on an API key.
-- Params: $1 id (UUID)
-- Returns: nothing
-- Plugin: api-key
UPDATE yauth_api_keys SET last_used_at = NOW() WHERE id = $1;
