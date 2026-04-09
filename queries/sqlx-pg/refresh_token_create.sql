-- Create a refresh token.
-- Params: $1 id (UUID), $2 user_id (UUID), $3 token_hash (VARCHAR(64)), $4 family_id (UUID), $5 expires_at (TIMESTAMPTZ)
-- Returns: nothing
-- Plugin: bearer
INSERT INTO yauth_refresh_tokens (id, user_id, token_hash, family_id, expires_at, revoked, created_at)
VALUES ($1, $2, $3, $4, $5, false, NOW());
