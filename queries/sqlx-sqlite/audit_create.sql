-- Create an audit log entry.
-- Params: ? id (TEXT), ? user_id (TEXT, nullable), ? event_type (VARCHAR), ? metadata (JSONB, nullable), ? ip_address (VARCHAR, nullable)
-- Returns: nothing
-- Plugin: core
INSERT INTO yauth_audit_log (id, user_id, event_type, metadata, ip_address, created_at)
VALUES (?, ?, ?, ?, ?, datetime('now'));
