-- Revoke all refresh tokens in a rotation family.
-- Params: $1 family_id (UUID)
-- Returns: nothing
-- Plugin: bearer
UPDATE yauth_refresh_tokens SET revoked = true WHERE family_id = $1;
