-- Find an OAuth account by provider and provider user ID.
-- Params: $1 provider (VARCHAR), $2 provider_user_id (VARCHAR)
-- Returns: OAuth account row or empty
-- Plugin: oauth
SELECT * FROM yauth_oauth_accounts WHERE provider = $1 AND provider_user_id = $2;
