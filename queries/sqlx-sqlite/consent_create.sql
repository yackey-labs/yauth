-- Create a consent record.
-- Params: ? id (TEXT), ? user_id (TEXT), ? client_id (VARCHAR), ? scopes (JSON, nullable)
-- Returns: nothing
-- Plugin: oauth2-server
INSERT INTO yauth_consents (id, user_id, client_id, scopes, created_at)
VALUES (?, ?, ?, ?, datetime('now'));
