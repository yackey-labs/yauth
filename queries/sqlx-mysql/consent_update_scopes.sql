-- Update scopes on a consent record.
-- Params: ? scopes (JSON, nullable), ? id (CHAR(36))
-- Returns: nothing
-- Plugin: oauth2-server
UPDATE yauth_consents SET scopes = ? WHERE id = ?;
