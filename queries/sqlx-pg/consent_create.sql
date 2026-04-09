-- Create a consent record.
-- Params: $1 id (UUID), $2 user_id (UUID), $3 client_id (VARCHAR), $4 scopes (JSON, nullable)
-- Returns: nothing
-- Plugin: oauth2-server
INSERT INTO yauth_consents (id, user_id, client_id, scopes, created_at)
VALUES ($1, $2, $3, $4, NOW());
