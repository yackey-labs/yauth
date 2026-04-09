-- Create a new session.
-- Params: ? id (TEXT), ? user_id (TEXT), ? token_hash (VARCHAR(64)), ? ip_address (VARCHAR, nullable), ? user_agent (VARCHAR, nullable), ? expires_at (TIMESTAMPTZ)
-- Returns: nothing
-- Plugin: core
INSERT INTO yauth_sessions (id, user_id, token_hash, ip_address, user_agent, expires_at, created_at)
VALUES (?, ?, ?, ?, ?, ?, datetime('now'));
