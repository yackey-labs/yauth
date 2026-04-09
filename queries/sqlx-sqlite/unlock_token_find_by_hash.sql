-- Find a valid unlock token by hash.
-- Params: ? token_hash (VARCHAR)
-- Returns: token row or empty
-- Plugin: account-lockout
SELECT * FROM yauth_unlock_tokens WHERE token_hash = ? AND expires_at > datetime('now');
