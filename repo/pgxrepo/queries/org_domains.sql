-- name: CreateOrganizationDomain :one
INSERT INTO yauth_organization_domains (id, organization_id, domain, domain_canonical, status, verification_token, verified_at, last_checked_at, auto_join_on_signup, default_role_on_auto_join, require_email_verified, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
RETURNING *;

-- name: GetOrganizationDomainByID :one
SELECT * FROM yauth_organization_domains WHERE id = $1 LIMIT 1;

-- name: GetOrganizationDomainByDomain :one
SELECT * FROM yauth_organization_domains WHERE domain_canonical = $1 LIMIT 1;

-- name: ListOrganizationDomainsByOrg :many
SELECT * FROM yauth_organization_domains WHERE organization_id = $1 ORDER BY created_at ASC, id ASC;

-- name: ListVerifiedAutoJoinOrganizationDomains :many
SELECT * FROM yauth_organization_domains
WHERE domain_canonical = $1 AND status = 'verified' AND auto_join_on_signup = true
ORDER BY created_at ASC, id ASC;

-- name: UpdateOrganizationDomain :one
UPDATE yauth_organization_domains
SET
    auto_join_on_signup       = COALESCE(sqlc.narg('auto_join_on_signup'), auto_join_on_signup),
    default_role_on_auto_join = COALESCE(sqlc.narg('default_role_on_auto_join'), default_role_on_auto_join),
    require_email_verified    = COALESCE(sqlc.narg('require_email_verified'), require_email_verified),
    updated_at                = $1
WHERE id = $2
RETURNING *;

-- name: SetOrganizationDomainVerification :one
UPDATE yauth_organization_domains
SET status = $2, verified_at = $3, last_checked_at = $4, updated_at = $4
WHERE id = $1
RETURNING *;

-- name: DeleteOrganizationDomain :execrows
DELETE FROM yauth_organization_domains WHERE id = $1;

-- name: GetOrganizationPolicy :one
SELECT * FROM yauth_organization_policies WHERE organization_id = $1 LIMIT 1;

-- name: CreateOrganizationPolicy :one
INSERT INTO yauth_organization_policies (organization_id, max_session_duration_secs, idle_timeout_secs, mfa_required, mfa_grace_period_days, ip_allowlist_json, max_concurrent_sessions, auth_methods_json, session_binding, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
RETURNING *;

-- name: UpdateOrganizationPolicy :one
UPDATE yauth_organization_policies
SET
    max_session_duration_secs = CASE WHEN sqlc.arg('set_max_session')::boolean     THEN sqlc.narg('max_session_duration_secs') ELSE max_session_duration_secs END,
    idle_timeout_secs         = CASE WHEN sqlc.arg('set_idle_timeout')::boolean    THEN sqlc.narg('idle_timeout_secs')         ELSE idle_timeout_secs         END,
    mfa_required              = COALESCE(sqlc.narg('mfa_required'), mfa_required),
    mfa_grace_period_days     = COALESCE(sqlc.narg('mfa_grace_period_days'), mfa_grace_period_days),
    ip_allowlist_json         = CASE WHEN sqlc.arg('set_ip_allowlist')::boolean    THEN sqlc.narg('ip_allowlist_json')         ELSE ip_allowlist_json         END,
    max_concurrent_sessions   = CASE WHEN sqlc.arg('set_max_concurrent')::boolean  THEN sqlc.narg('max_concurrent_sessions')   ELSE max_concurrent_sessions   END,
    auth_methods_json         = CASE WHEN sqlc.arg('set_auth_methods')::boolean    THEN sqlc.narg('auth_methods_json')         ELSE auth_methods_json         END,
    session_binding           = COALESCE(sqlc.narg('session_binding'), session_binding),
    updated_at                = $1
WHERE organization_id = $2
RETURNING *;

-- name: UpsertOrganizationPolicy :one
INSERT INTO yauth_organization_policies (organization_id, max_session_duration_secs, idle_timeout_secs, mfa_required, mfa_grace_period_days, ip_allowlist_json, max_concurrent_sessions, auth_methods_json, session_binding, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
ON CONFLICT (organization_id) DO UPDATE
SET
    max_session_duration_secs = EXCLUDED.max_session_duration_secs,
    idle_timeout_secs         = EXCLUDED.idle_timeout_secs,
    mfa_required              = EXCLUDED.mfa_required,
    mfa_grace_period_days     = EXCLUDED.mfa_grace_period_days,
    ip_allowlist_json         = EXCLUDED.ip_allowlist_json,
    max_concurrent_sessions   = EXCLUDED.max_concurrent_sessions,
    auth_methods_json         = EXCLUDED.auth_methods_json,
    session_binding           = EXCLUDED.session_binding,
    updated_at                = EXCLUDED.updated_at
RETURNING *;

-- name: DeleteOrganizationPolicy :execrows
DELETE FROM yauth_organization_policies WHERE organization_id = $1;
