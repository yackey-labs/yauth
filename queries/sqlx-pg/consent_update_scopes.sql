-- Update scopes on a consent record.
-- Params: $1 scopes (JSON, nullable), $2 id (UUID)
-- Returns: nothing
-- Plugin: oauth2-server
UPDATE yauth_consents SET scopes = $1 WHERE id = $2;
