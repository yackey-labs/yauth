-- Find a valid unlock token by hash.
-- Params: $1 token_hash (VARCHAR)
-- Returns: token row or empty
-- Plugin: account-lockout
SELECT * FROM yauth_unlock_tokens WHERE token_hash = $1 AND expires_at > NOW();
