-- List all API keys for a user.
-- Params: ? user_id (CHAR(36))
-- Returns: API key rows
-- Plugin: api-key
SELECT * FROM yauth_api_keys WHERE user_id = ?;
