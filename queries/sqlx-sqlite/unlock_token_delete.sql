-- Delete an unlock token.
-- Params: ? id (TEXT)
-- Returns: nothing
-- Plugin: account-lockout
DELETE FROM yauth_unlock_tokens WHERE id = ?;
