-- Delete an unlock token.
-- Params: $1 id (UUID)
-- Returns: nothing
-- Plugin: account-lockout
DELETE FROM yauth_unlock_tokens WHERE id = $1;
