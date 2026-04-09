-- Find all OAuth accounts for a user.
-- Params: ? user_id (TEXT)
-- Returns: OAuth account rows
-- Plugin: oauth
SELECT * FROM yauth_oauth_accounts WHERE user_id = ?;
