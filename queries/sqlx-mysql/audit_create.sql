-- Create an audit log entry.
-- Params: ? id (CHAR(36)), ? user_id (CHAR(36), nullable), ? event_type (VARCHAR), ? metadata (JSONB, nullable), ? ip_address (VARCHAR, nullable)
-- Returns: nothing
-- Plugin: core
INSERT INTO yauth_audit_log (id, user_id, event_type, metadata, ip_address, created_at)
VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP);
