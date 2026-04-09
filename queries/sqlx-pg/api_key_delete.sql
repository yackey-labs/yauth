-- Delete an API key.
-- Params: $1 id (UUID)
-- Returns: nothing
-- Plugin: api-key
DELETE FROM yauth_api_keys WHERE id = $1;
