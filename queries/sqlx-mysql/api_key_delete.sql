-- Delete an API key.
-- Params: ? id (CHAR(36))
-- Returns: nothing
-- Plugin: api-key
DELETE FROM yauth_api_keys WHERE id = ?;
