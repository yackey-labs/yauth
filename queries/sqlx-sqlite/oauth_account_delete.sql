-- Unlink an OAuth account.
-- Params: ? id (TEXT)
-- Returns: nothing
-- Plugin: oauth
DELETE FROM yauth_oauth_accounts WHERE id = ?;
