-- Find an OAuth2 client by client_id.
-- Params: ? client_id (VARCHAR)
-- Returns: client row or empty
-- Plugin: oauth2-server
SELECT * FROM yauth_oauth2_clients WHERE client_id = ?;
