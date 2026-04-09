-- Mark an authorization code as used.
-- Params: $1 id (UUID)
-- Returns: nothing
-- Plugin: oauth2-server
UPDATE yauth_authorization_codes SET used = true WHERE id = $1;
