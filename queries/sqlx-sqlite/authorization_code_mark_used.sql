-- Mark an authorization code as used.
-- Params: ? id (TEXT)
-- Returns: nothing
-- Plugin: oauth2-server
UPDATE yauth_authorization_codes SET used = true WHERE id = ?;
