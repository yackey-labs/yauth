-- Register an OAuth2 client.
-- Params: $1 id (UUID), $2 client_id (VARCHAR), $3 client_secret_hash (VARCHAR, nullable), $4 redirect_uris (JSON), $5 client_name (VARCHAR, nullable), $6 grant_types (JSON), $7 scopes (JSON, nullable), $8 is_public (BOOLEAN)
-- Returns: nothing
-- Plugin: oauth2-server
INSERT INTO yauth_oauth2_clients (id, client_id, client_secret_hash, redirect_uris, client_name, grant_types, scopes, is_public, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW());
