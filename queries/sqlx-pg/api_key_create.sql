-- Create an API key.
-- Params: $1 id (UUID), $2 user_id (UUID), $3 key_prefix (VARCHAR(12)), $4 key_hash (VARCHAR(64)), $5 name (VARCHAR), $6 scopes (JSON, nullable), $7 expires_at (TIMESTAMPTZ, nullable)
-- Returns: nothing
-- Plugin: api-key
INSERT INTO yauth_api_keys (id, user_id, key_prefix, key_hash, name, scopes, expires_at, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, NOW());
