-- Create an authorization code.
-- Params: $1 id (UUID), $2 code_hash (VARCHAR), $3 client_id (VARCHAR), $4 user_id (UUID), $5 scopes (JSON, nullable), $6 redirect_uri (VARCHAR), $7 code_challenge (VARCHAR), $8 code_challenge_method (VARCHAR), $9 expires_at (TIMESTAMPTZ), $10 nonce (VARCHAR, nullable)
-- Returns: nothing
-- Plugin: oauth2-server
INSERT INTO yauth_authorization_codes (id, code_hash, client_id, user_id, scopes, redirect_uri, code_challenge, code_challenge_method, expires_at, used, nonce, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, false, $10, NOW());
