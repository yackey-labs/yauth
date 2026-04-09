-- Revoke all refresh tokens in a rotation family.
-- Params: ? family_id (CHAR(36))
-- Returns: nothing
-- Plugin: bearer
UPDATE yauth_refresh_tokens SET revoked = true WHERE family_id = ?;
