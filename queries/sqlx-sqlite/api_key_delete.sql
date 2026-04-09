-- Delete an API key.
-- Params: ? id (TEXT)
-- Returns: nothing
-- Plugin: api-key
DELETE FROM yauth_api_keys WHERE id = ?;
