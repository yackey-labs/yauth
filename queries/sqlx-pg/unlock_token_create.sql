-- Create an unlock token.
-- Params: $1 id (UUID), $2 user_id (UUID), $3 token_hash (VARCHAR), $4 expires_at (TIMESTAMPTZ)
-- Returns: nothing
-- Plugin: account-lockout
INSERT INTO yauth_unlock_tokens (id, user_id, token_hash, expires_at, created_at)
VALUES ($1, $2, $3, $4, NOW());
