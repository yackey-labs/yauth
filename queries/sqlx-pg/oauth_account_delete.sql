-- Unlink an OAuth account.
-- Params: $1 id (UUID)
-- Returns: nothing
-- Plugin: oauth
DELETE FROM yauth_oauth_accounts WHERE id = $1;
