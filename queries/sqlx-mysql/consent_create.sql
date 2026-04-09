-- Create a consent record.
-- Params: ? id (CHAR(36)), ? user_id (CHAR(36)), ? client_id (VARCHAR), ? scopes (JSON, nullable)
-- Returns: nothing
-- Plugin: oauth2-server
INSERT INTO yauth_consents (id, user_id, client_id, scopes, created_at)
VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP);
