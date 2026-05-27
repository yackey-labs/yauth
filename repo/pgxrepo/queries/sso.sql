-- name: CreateSsoConnection :one
INSERT INTO yauth_sso_connections (id, organization_id, kind, name, status, config, jit_provisioning_enabled, default_role_on_jit, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
RETURNING *;

-- name: GetSsoConnectionByID :one
SELECT * FROM yauth_sso_connections WHERE id = $1 LIMIT 1;

-- name: ListSsoConnectionsByOrg :many
SELECT * FROM yauth_sso_connections WHERE organization_id = $1 ORDER BY created_at ASC, id ASC;

-- name: UpdateSsoConnection :one
UPDATE yauth_sso_connections
SET
    name                     = COALESCE(sqlc.narg('name'), name),
    status                   = COALESCE(sqlc.narg('status'), status),
    config                   = COALESCE(sqlc.narg('config'), config),
    jit_provisioning_enabled = COALESCE(sqlc.narg('jit_provisioning_enabled'), jit_provisioning_enabled),
    default_role_on_jit      = COALESCE(sqlc.narg('default_role_on_jit'), default_role_on_jit),
    updated_at               = $1
WHERE id = $2
RETURNING *;

-- name: DeleteSsoConnection :execrows
DELETE FROM yauth_sso_connections WHERE id = $1;

-- name: CreateExternalIdentity :one
INSERT INTO yauth_external_identities (id, user_id, provider, external_id, linked_at, last_login_at)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: GetExternalIdentityByProviderAndExternalID :one
SELECT * FROM yauth_external_identities WHERE provider = $1 AND external_id = $2 LIMIT 1;

-- name: ListExternalIdentitiesByUser :many
SELECT * FROM yauth_external_identities WHERE user_id = $1 ORDER BY linked_at ASC, id ASC;

-- name: UpdateExternalIdentityLastLogin :execrows
UPDATE yauth_external_identities SET last_login_at = $2 WHERE id = $1;

-- name: DeleteExternalIdentity :execrows
DELETE FROM yauth_external_identities WHERE id = $1;

-- name: CreateSsoLoginState :exec
INSERT INTO yauth_sso_login_states (state, connection_id, nonce, pkce_verifier, redirect_url, created_at, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7);

-- name: ConsumeSsoLoginState :one
DELETE FROM yauth_sso_login_states WHERE state = $1 AND expires_at > NOW() RETURNING *;
