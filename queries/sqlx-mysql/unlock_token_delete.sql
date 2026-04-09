-- Delete an unlock token.
-- Params: ? id (CHAR(36))
-- Returns: nothing
-- Plugin: account-lockout
DELETE FROM yauth_unlock_tokens WHERE id = ?;
