-- List all API keys for a user.
-- Params: $1 user_id (UUID)
-- Returns: API key rows
-- Plugin: api-key
SELECT * FROM yauth_api_keys WHERE user_id = $1;
