-- Find consent record for user and client.
-- Params: $1 user_id (UUID), $2 client_id (VARCHAR)
-- Returns: consent row or empty
-- Plugin: oauth2-server
SELECT * FROM yauth_consents WHERE user_id = $1 AND client_id = $2;
