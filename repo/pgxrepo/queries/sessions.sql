-- name: CreateSession :exec
INSERT INTO yauth_sessions (id, user_id, token_hash, ip_address, user_agent, active_org_id, expires_at, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8);

-- name: GetSessionByTokenHash :one
SELECT * FROM yauth_sessions WHERE token_hash = $1 LIMIT 1;

-- name: GetSessionByID :one
SELECT * FROM yauth_sessions WHERE id = $1 LIMIT 1;

-- name: DeleteSession :one
DELETE FROM yauth_sessions WHERE token_hash = $1 RETURNING id;

-- name: DeleteSessionByID :execrows
DELETE FROM yauth_sessions WHERE id = $1;

-- name: DeleteUserSessions :execrows
DELETE FROM yauth_sessions WHERE user_id = $1;

-- name: DeleteOtherUserSessions :execrows
DELETE FROM yauth_sessions WHERE user_id = $1 AND token_hash != $2;

-- name: DeleteExpiredSessions :execrows
DELETE FROM yauth_sessions WHERE expires_at <= $1;

-- name: SetSessionActiveOrg :execrows
UPDATE yauth_sessions SET active_org_id = $2 WHERE id = $1;

-- name: ListSessionsByUser :many
SELECT * FROM yauth_sessions
WHERE user_id = $1
ORDER BY created_at DESC, id ASC
LIMIT CASE WHEN $2::int > 0 THEN $2::int ELSE NULL END
OFFSET $3::int;

-- name: ListAllSessions :many
SELECT * FROM yauth_sessions
ORDER BY created_at DESC, id ASC
LIMIT CASE WHEN $1::int > 0 THEN $1::int ELSE NULL END
OFFSET $2::int;

-- name: CountSessionsByUser :one
SELECT COUNT(*) FROM yauth_sessions WHERE user_id = $1;

-- name: CountAllSessions :one
SELECT COUNT(*) FROM yauth_sessions;
