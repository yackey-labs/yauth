-- name: AssignClientRole :exec
INSERT INTO yauth_client_role_assignments (id, client_id, role, group_id, user_id, created_at)
VALUES ($1, $2, $3, $4, $5, $6);

-- name: UnassignClientRole :exec
DELETE FROM yauth_client_role_assignments WHERE id = $1;

-- name: ListClientRoleAssignments :many
SELECT * FROM yauth_client_role_assignments WHERE client_id = $1 ORDER BY role;

-- name: ResolveUserRolesForClient :many
SELECT DISTINCT cra.role FROM yauth_client_role_assignments cra
WHERE cra.client_id = $1 AND (
  cra.user_id = $2
  OR cra.group_id IN (SELECT gm.group_id FROM yauth_group_members gm WHERE gm.user_id = $2)
)
ORDER BY cra.role;
