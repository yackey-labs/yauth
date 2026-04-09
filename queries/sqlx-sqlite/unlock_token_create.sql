-- Create an unlock token.
-- Params: ? id (TEXT), ? user_id (TEXT), ? token_hash (VARCHAR), ? expires_at (TIMESTAMPTZ)
-- Returns: nothing
-- Plugin: account-lockout
INSERT INTO yauth_unlock_tokens (id, user_id, token_hash, expires_at, created_at)
VALUES (?, ?, ?, ?, datetime('now'));
