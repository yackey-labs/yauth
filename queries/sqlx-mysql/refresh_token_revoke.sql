-- Revoke a single refresh token.
-- Params: ? id (CHAR(36))
-- Returns: nothing
-- Plugin: bearer
UPDATE yauth_refresh_tokens SET revoked = true WHERE id = ?;
