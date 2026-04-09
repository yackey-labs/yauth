-- Find an API key by ID and user.
-- Params: $1 id (UUID), $2 user_id (UUID)
-- Returns: API key row or empty
-- Plugin: api-key
SELECT * FROM yauth_api_keys WHERE id = $1 AND user_id = $2;
