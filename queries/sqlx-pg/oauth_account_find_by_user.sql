-- Find all OAuth accounts for a user.
-- Params: $1 user_id (UUID)
-- Returns: OAuth account rows
-- Plugin: oauth
SELECT * FROM yauth_oauth_accounts WHERE user_id = $1;
