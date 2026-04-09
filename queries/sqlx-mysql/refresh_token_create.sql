-- Create a refresh token.
-- Params: ? id (CHAR(36)), ? user_id (CHAR(36)), ? token_hash (VARCHAR(64)), ? family_id (CHAR(36)), ? expires_at (TIMESTAMPTZ)
-- Returns: nothing
-- Plugin: bearer
INSERT INTO yauth_refresh_tokens (id, user_id, token_hash, family_id, expires_at, revoked, created_at)
VALUES (?, ?, ?, ?, ?, false, CURRENT_TIMESTAMP);
