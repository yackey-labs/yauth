-- Create a refresh token.
-- Params: ? id (TEXT), ? user_id (TEXT), ? token_hash (VARCHAR(64)), ? family_id (TEXT), ? expires_at (TIMESTAMPTZ)
-- Returns: nothing
-- Plugin: bearer
INSERT INTO yauth_refresh_tokens (id, user_id, token_hash, family_id, expires_at, revoked, created_at)
VALUES (?, ?, ?, ?, ?, false, datetime('now'));
