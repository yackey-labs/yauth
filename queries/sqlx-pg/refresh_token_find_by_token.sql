-- Find a refresh token by hash.
-- Params: $1 token_hash (VARCHAR(64))
-- Returns: refresh token row or empty
-- Plugin: bearer
SELECT * FROM yauth_refresh_tokens WHERE token_hash = $1;
