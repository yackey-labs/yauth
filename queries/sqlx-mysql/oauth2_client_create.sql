-- Register an OAuth2 client.
-- Params: ? id (CHAR(36)), ? client_id (VARCHAR), ? client_secret_hash (VARCHAR, nullable), ? redirect_uris (JSON), ? client_name (VARCHAR, nullable), ? grant_types (JSON), ? scopes (JSON, nullable), ? is_public (BOOLEAN)
-- Returns: nothing
-- Plugin: oauth2-server
INSERT INTO yauth_oauth2_clients (id, client_id, client_secret_hash, redirect_uris, client_name, grant_types, scopes, is_public, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP);
