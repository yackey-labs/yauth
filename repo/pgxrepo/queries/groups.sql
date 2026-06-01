-- name: CreateGroup :one
INSERT INTO yauth_groups (id, organization_id, name, description, external_id, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING *;

-- name: GetGroupByID :one
SELECT * FROM yauth_groups WHERE id = $1 LIMIT 1;

-- name: GetGroupByOrgAndName :one
SELECT * FROM yauth_groups WHERE organization_id = $1 AND name = $2 LIMIT 1;

-- name: GetGroupByOrgAndExternalID :one
SELECT * FROM yauth_groups WHERE organization_id = $1 AND external_id = $2 LIMIT 1;

-- name: ListGroupsByOrg :many
SELECT * FROM yauth_groups WHERE organization_id = $1 ORDER BY name;

-- name: UpdateGroup :one
UPDATE yauth_groups
SET name = $2, description = $3, external_id = $4, updated_at = $5
WHERE id = $1
RETURNING *;

-- name: DeleteGroup :exec
DELETE FROM yauth_groups WHERE id = $1;

-- name: AddGroupMember :exec
INSERT INTO yauth_group_members (group_id, user_id, created_at)
VALUES ($1, $2, $3)
ON CONFLICT (group_id, user_id) DO NOTHING;

-- name: RemoveGroupMember :exec
DELETE FROM yauth_group_members WHERE group_id = $1 AND user_id = $2;

-- name: ListGroupMembers :many
SELECT u.* FROM yauth_users u
JOIN yauth_group_members gm ON gm.user_id = u.id
WHERE gm.group_id = $1
ORDER BY u.email;

-- name: ListGroupsForUser :many
SELECT g.* FROM yauth_groups g
JOIN yauth_group_members gm ON gm.group_id = g.id
WHERE g.organization_id = $1 AND gm.user_id = $2
ORDER BY g.name;

-- name: IsGroupMember :one
SELECT EXISTS(SELECT 1 FROM yauth_group_members WHERE group_id = $1 AND user_id = $2);

-- name: ListGroupNamesForUser :many
SELECT DISTINCT g.name FROM yauth_groups g
JOIN yauth_group_members gm ON gm.group_id = g.id
WHERE gm.user_id = $1
ORDER BY g.name;

-- name: AssignClientGroup :exec
INSERT INTO yauth_client_group_assignments (client_id, group_id, created_at)
VALUES ($1, $2, $3)
ON CONFLICT (client_id, group_id) DO NOTHING;

-- name: UnassignClientGroup :exec
DELETE FROM yauth_client_group_assignments WHERE client_id = $1 AND group_id = $2;

-- name: ListClientGroups :many
SELECT g.* FROM yauth_groups g
JOIN yauth_client_group_assignments a ON a.group_id = g.id
WHERE a.client_id = $1
ORDER BY g.name;

-- name: UserInAssignedGroup :one
SELECT EXISTS(
  SELECT 1 FROM yauth_client_group_assignments a
  JOIN yauth_group_members gm ON gm.group_id = a.group_id
  WHERE a.client_id = $1 AND gm.user_id = $2
);
