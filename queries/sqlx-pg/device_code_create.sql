-- Create a device code.
-- Params: $1 id (UUID), $2 device_code_hash (VARCHAR), $3 user_code (VARCHAR), $4 client_id (VARCHAR), $5 scopes (JSON, nullable), $6 expires_at (TIMESTAMPTZ)
-- Returns: nothing
-- Plugin: oauth2-server
INSERT INTO yauth_device_codes (id, device_code_hash, user_code, client_id, scopes, status, interval, expires_at, created_at)
VALUES ($1, $2, $3, $4, $5, 'pending', 5, $6, NOW());
