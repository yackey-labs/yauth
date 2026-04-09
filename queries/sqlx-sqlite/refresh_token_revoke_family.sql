-- Revoke all refresh tokens in a rotation family.
-- Params: ? family_id (TEXT)
-- Returns: nothing
-- Plugin: bearer
UPDATE yauth_refresh_tokens SET revoked = true WHERE family_id = ?;
