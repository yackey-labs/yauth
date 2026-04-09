-- Find consent record for user and client.
-- Params: ? user_id (CHAR(36)), ? client_id (VARCHAR)
-- Returns: consent row or empty
-- Plugin: oauth2-server
SELECT * FROM yauth_consents WHERE user_id = ? AND client_id = ?;
