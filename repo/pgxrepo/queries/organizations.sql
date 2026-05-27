-- name: CreateOrganization :one
INSERT INTO yauth_organizations (id, name, slug, slug_lower, display_name, avatar_url, metadata, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
RETURNING *;

-- name: GetOrganizationByID :one
SELECT * FROM yauth_organizations WHERE id = $1 LIMIT 1;

-- name: GetOrganizationBySlug :one
SELECT * FROM yauth_organizations WHERE slug_lower = $1 LIMIT 1;

-- name: UpdateOrganization :one
UPDATE yauth_organizations
SET
    name         = COALESCE(sqlc.narg('name'), name),
    slug         = COALESCE(sqlc.narg('slug'), slug),
    slug_lower   = COALESCE(sqlc.narg('slug_lower'), slug_lower),
    display_name = CASE WHEN sqlc.arg('set_display_name')::boolean THEN sqlc.narg('display_name') ELSE display_name END,
    avatar_url   = CASE WHEN sqlc.arg('set_avatar_url')::boolean   THEN sqlc.narg('avatar_url')   ELSE avatar_url   END,
    metadata     = CASE WHEN sqlc.arg('set_metadata')::boolean     THEN sqlc.narg('metadata')     ELSE metadata     END,
    updated_at   = $1
WHERE id = $2
RETURNING *;

-- name: DeleteOrganization :exec
DELETE FROM yauth_organizations WHERE id = $1;

-- name: DeleteOrganizationCascade :exec
DELETE FROM yauth_organizations WHERE id = $1;

-- name: ListOrganizationsForUser :many
SELECT o.* FROM yauth_organizations o
INNER JOIN yauth_memberships m ON m.organization_id = o.id
WHERE m.user_id = $1
ORDER BY o.created_at ASC, o.id ASC;

-- name: ListOrganizationsSearch :many
SELECT * FROM yauth_organizations
WHERE ($1::text = '' OR LOWER(name) LIKE '%' || LOWER($1::text) || '%' OR slug_lower LIKE '%' || LOWER($1::text) || '%')
ORDER BY created_at ASC, id ASC
LIMIT CASE WHEN $2::int > 0 THEN $2::int ELSE NULL END
OFFSET $3::int;

-- name: CountOrganizationsSearch :one
SELECT COUNT(*) FROM yauth_organizations
WHERE ($1::text = '' OR LOWER(name) LIKE '%' || LOWER($1::text) || '%' OR slug_lower LIKE '%' || LOWER($1::text) || '%');

-- name: CreateMembership :one
INSERT INTO yauth_memberships (id, organization_id, user_id, role, status, invited_at, joined_at, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
RETURNING *;

-- name: GetMembershipByID :one
SELECT * FROM yauth_memberships WHERE id = $1 LIMIT 1;

-- name: GetMembershipByOrgUser :one
SELECT * FROM yauth_memberships WHERE organization_id = $1 AND user_id = $2 LIMIT 1;

-- name: UpdateMembership :one
UPDATE yauth_memberships
SET
    role       = COALESCE(sqlc.narg('role'), role),
    status     = COALESCE(sqlc.narg('status'), status),
    joined_at  = CASE WHEN sqlc.arg('set_joined_at')::boolean THEN sqlc.narg('joined_at') ELSE joined_at END,
    updated_at = $1
WHERE id = $2
RETURNING *;

-- name: DeleteMembership :execrows
DELETE FROM yauth_memberships WHERE id = $1;

-- name: CountOrgOwners :one
SELECT COUNT(*) FROM yauth_memberships WHERE organization_id = $1 AND role = 'owner';

-- name: ListMembershipsByOrg :many
SELECT * FROM yauth_memberships WHERE organization_id = $1 ORDER BY created_at ASC, id ASC;

-- name: ListMembershipsByUser :many
SELECT * FROM yauth_memberships WHERE user_id = $1 ORDER BY created_at ASC, id ASC;

-- name: CreateInvitation :one
INSERT INTO yauth_invitations (id, organization_id, email, role, token_hash, invited_by_user_id, expires_at, accepted_at, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
RETURNING *;

-- name: GetInvitationByID :one
SELECT * FROM yauth_invitations WHERE id = $1 LIMIT 1;

-- name: GetInvitationByTokenHash :one
SELECT * FROM yauth_invitations
WHERE token_hash = $1 AND accepted_at IS NULL AND expires_at > NOW()
LIMIT 1;

-- name: MarkInvitationAccepted :one
UPDATE yauth_invitations
SET accepted_at = $2
WHERE id = $1 AND accepted_at IS NULL
RETURNING *;

-- name: DeleteInvitation :execrows
DELETE FROM yauth_invitations WHERE id = $1;

-- name: ListPendingInvitationsForOrg :many
SELECT * FROM yauth_invitations
WHERE organization_id = $1 AND accepted_at IS NULL
ORDER BY created_at ASC, id ASC;
