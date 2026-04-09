-- Create an audit log entry.
-- Params: $1 id (UUID), $2 user_id (UUID, nullable), $3 event_type (VARCHAR), $4 metadata (JSONB, nullable), $5 ip_address (VARCHAR, nullable)
-- Returns: nothing
-- Plugin: core
INSERT INTO yauth_audit_log (id, user_id, event_type, metadata, ip_address, created_at)
VALUES ($1, $2, $3, $4, $5, NOW());
