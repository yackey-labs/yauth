-- Create an authorization code.
-- Params: ? id (TEXT), ? code_hash (VARCHAR), ? client_id (VARCHAR), ? user_id (TEXT), ? scopes (JSON, nullable), ? redirect_uri (VARCHAR), ? code_challenge (VARCHAR), ? code_challenge_method (VARCHAR), ? expires_at (TIMESTAMPTZ), ? nonce (VARCHAR, nullable)
-- Returns: nothing
-- Plugin: oauth2-server
INSERT INTO yauth_authorization_codes (id, code_hash, client_id, user_id, scopes, redirect_uri, code_challenge, code_challenge_method, expires_at, used, nonce, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, false, ?, datetime('now'));
