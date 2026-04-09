-- Find all OAuth accounts for a user.
-- Params: ? user_id (CHAR(36))
-- Returns: OAuth account rows
-- Plugin: oauth
SELECT * FROM yauth_oauth_accounts WHERE user_id = ?;
