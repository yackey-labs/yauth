-- name: LogAuditEvent :exec
INSERT INTO yauth_audit_log (id, user_id, event_type, metadata, ip_address, created_at)
VALUES ($1, $2, $3, $4, $5, $6);

-- name: ListAuditLogByUserAndType :many
SELECT * FROM yauth_audit_log
WHERE
    ($1::text = '' OR user_id = $1::text)
    AND ($2::text = '' OR event_type = $2::text)
ORDER BY created_at DESC
LIMIT CASE WHEN $3::int > 0 THEN $3::int ELSE 100 END
OFFSET $4::int;
