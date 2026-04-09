-- Find an OAuth account by provider and provider user ID.
-- Params: ? provider (VARCHAR), ? provider_user_id (VARCHAR)
-- Returns: OAuth account row or empty
-- Plugin: oauth
SELECT * FROM yauth_oauth_accounts WHERE provider = ? AND provider_user_id = ?;
