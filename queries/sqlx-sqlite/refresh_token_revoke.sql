-- Revoke a single refresh token.
-- Params: ? id (TEXT)
-- Returns: nothing
-- Plugin: bearer
UPDATE yauth_refresh_tokens SET revoked = true WHERE id = ?;
