-- Create an API key.
-- Params: ? id (CHAR(36)), ? user_id (CHAR(36)), ? key_prefix (VARCHAR(12)), ? key_hash (VARCHAR(64)), ? name (VARCHAR), ? scopes (JSON, nullable), ? expires_at (TIMESTAMPTZ, nullable)
-- Returns: nothing
-- Plugin: api-key
INSERT INTO yauth_api_keys (id, user_id, key_prefix, key_hash, name, scopes, expires_at, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP);
