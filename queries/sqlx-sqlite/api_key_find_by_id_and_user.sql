-- Find an API key by ID and user.
-- Params: ? id (TEXT), ? user_id (TEXT)
-- Returns: API key row or empty
-- Plugin: api-key
SELECT * FROM yauth_api_keys WHERE id = ? AND user_id = ?;
