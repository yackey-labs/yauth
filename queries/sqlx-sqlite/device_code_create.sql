-- Create a device code.
-- Params: ? id (TEXT), ? device_code_hash (VARCHAR), ? user_code (VARCHAR), ? client_id (VARCHAR), ? scopes (JSON, nullable), ? expires_at (TIMESTAMPTZ)
-- Returns: nothing
-- Plugin: oauth2-server
INSERT INTO yauth_device_codes (id, device_code_hash, user_code, client_id, scopes, status, interval, expires_at, created_at)
VALUES (?, ?, ?, ?, ?, 'pending', 5, ?, datetime('now'));
