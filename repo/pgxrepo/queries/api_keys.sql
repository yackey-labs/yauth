-- name: CreateAPIKey :exec
INSERT INTO yauth_api_keys (id, user_id, organization_id, key_prefix, key_hash, name, scopes, role, last_used_at, expires_at, created_at, created_by_user_id)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12);

-- name: GetAPIKeyByPrefix :one
SELECT * FROM yauth_api_keys WHERE key_prefix = $1 LIMIT 1;

-- name: GetAPIKeyByIDAndUser :one
SELECT * FROM yauth_api_keys WHERE id = $1 AND user_id = $2 LIMIT 1;

-- name: GetAPIKeyByIDAndOrg :one
SELECT * FROM yauth_api_keys WHERE id = $1 AND organization_id = $2 LIMIT 1;

-- name: ListAPIKeysByUserID :many
SELECT * FROM yauth_api_keys WHERE user_id = $1 ORDER BY created_at DESC;

-- name: ListAPIKeysByOrgID :many
SELECT * FROM yauth_api_keys WHERE organization_id = $1 ORDER BY created_at DESC;

-- name: UpdateAPIKeyLastUsed :execrows
UPDATE yauth_api_keys SET last_used_at = $2 WHERE id = $1;

-- name: SetAPIKeyExpiry :execrows
UPDATE yauth_api_keys SET expires_at = $2 WHERE id = $1;

-- name: DeleteAPIKey :execrows
DELETE FROM yauth_api_keys WHERE id = $1;
