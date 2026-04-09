-- Revoke a single refresh token.
-- Params: $1 id (UUID)
-- Returns: nothing
-- Plugin: bearer
UPDATE yauth_refresh_tokens SET revoked = true WHERE id = $1;
