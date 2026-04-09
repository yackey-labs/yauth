-- Find an API key by ID and user.
-- Params: ? id (CHAR(36)), ? user_id (CHAR(36))
-- Returns: API key row or empty
-- Plugin: api-key
SELECT * FROM yauth_api_keys WHERE id = ? AND user_id = ?;
