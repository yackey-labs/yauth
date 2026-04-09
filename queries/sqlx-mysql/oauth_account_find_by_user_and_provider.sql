-- Find OAuth account for a user and specific provider.
-- Params: ? user_id (CHAR(36)), ? provider (VARCHAR)
-- Returns: OAuth account row or empty
-- Plugin: oauth
SELECT * FROM yauth_oauth_accounts WHERE user_id = ? AND provider = ?;
