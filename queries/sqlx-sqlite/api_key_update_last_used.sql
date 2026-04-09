-- Update last_used_at on an API key.
-- Params: ? id (TEXT)
-- Returns: nothing
-- Plugin: api-key
UPDATE yauth_api_keys SET last_used_at = datetime('now') WHERE id = ?;
