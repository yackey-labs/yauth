-- Find OAuth account for a user and specific provider.
-- Params: $1 user_id (UUID), $2 provider (VARCHAR)
-- Returns: OAuth account row or empty
-- Plugin: oauth
SELECT * FROM yauth_oauth_accounts WHERE user_id = $1 AND provider = $2;
