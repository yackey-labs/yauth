-- Create a new session.
-- Params: ? id (CHAR(36)), ? user_id (CHAR(36)), ? token_hash (VARCHAR(64)), ? ip_address (VARCHAR, nullable), ? user_agent (VARCHAR, nullable), ? expires_at (TIMESTAMPTZ)
-- Returns: nothing
-- Plugin: core
INSERT INTO yauth_sessions (id, user_id, token_hash, ip_address, user_agent, expires_at, created_at)
VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP);
