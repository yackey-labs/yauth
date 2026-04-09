-- Create a new session.
-- Params: $1 id (UUID), $2 user_id (UUID), $3 token_hash (VARCHAR(64)), $4 ip_address (VARCHAR, nullable), $5 user_agent (VARCHAR, nullable), $6 expires_at (TIMESTAMPTZ)
-- Returns: nothing
-- Plugin: core
INSERT INTO yauth_sessions (id, user_id, token_hash, ip_address, user_agent, expires_at, created_at)
VALUES ($1, $2, $3, $4, $5, $6, NOW());
