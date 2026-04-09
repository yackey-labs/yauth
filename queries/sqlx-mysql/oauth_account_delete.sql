-- Unlink an OAuth account.
-- Params: ? id (CHAR(36))
-- Returns: nothing
-- Plugin: oauth
DELETE FROM yauth_oauth_accounts WHERE id = ?;
