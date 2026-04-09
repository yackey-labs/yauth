-- Update last_used_at on an API key.
-- Params: ? id (CHAR(36))
-- Returns: nothing
-- Plugin: api-key
UPDATE yauth_api_keys SET last_used_at = CURRENT_TIMESTAMP WHERE id = ?;
