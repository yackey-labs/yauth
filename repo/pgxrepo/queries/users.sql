-- name: CreateUser :one
INSERT INTO yauth_users (id, email, display_name, email_verified, role, banned, banned_reason, banned_until, suspended_at, suspended_reason, activates_at, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
RETURNING *;

-- name: GetUserByID :one
SELECT * FROM yauth_users WHERE id = $1 LIMIT 1;

-- name: GetUserByEmail :one
SELECT * FROM yauth_users WHERE email = $1 LIMIT 1;

-- name: UpdateUserFull :one
UPDATE yauth_users
SET
    email          = COALESCE(sqlc.narg('email'), email),
    display_name   = CASE WHEN sqlc.arg('set_display_name')::boolean THEN sqlc.narg('display_name') ELSE display_name END,
    email_verified = COALESCE(sqlc.narg('email_verified'), email_verified),
    role           = COALESCE(sqlc.narg('role'), role),
    banned         = COALESCE(sqlc.narg('banned'), banned),
    banned_reason  = CASE WHEN sqlc.arg('set_banned_reason')::boolean THEN sqlc.narg('banned_reason') ELSE banned_reason END,
    banned_until   = CASE WHEN sqlc.arg('set_banned_until')::boolean THEN sqlc.narg('banned_until') ELSE banned_until END,
    suspended_at      = CASE WHEN sqlc.arg('set_suspended_at')::boolean THEN sqlc.narg('suspended_at') ELSE suspended_at END,
    suspended_reason  = CASE WHEN sqlc.arg('set_suspended_reason')::boolean THEN sqlc.narg('suspended_reason') ELSE suspended_reason END,
    activates_at      = CASE WHEN sqlc.arg('set_activates_at')::boolean THEN sqlc.narg('activates_at') ELSE activates_at END,
    updated_at     = $1
WHERE id = $2
RETURNING *;

-- name: RevokeAllUserRefreshTokens :execrows
UPDATE yauth_refresh_tokens SET revoked = true WHERE user_id = $1 AND revoked = false;

-- name: DeleteUser :execrows
DELETE FROM yauth_users WHERE id = $1;

-- name: AnyUserExists :one
SELECT EXISTS(SELECT 1 FROM yauth_users LIMIT 1);

-- name: ListUsersSearch :many
SELECT * FROM yauth_users
WHERE ($1::text = '' OR LOWER(email) LIKE '%' || LOWER($1::text) || '%' OR LOWER(COALESCE(display_name, '')) LIKE '%' || LOWER($1::text) || '%')
ORDER BY created_at ASC, id ASC
LIMIT CASE WHEN $2::int > 0 THEN $2::int ELSE NULL END
OFFSET $3::int;

-- name: CountUsersSearch :one
SELECT COUNT(*) FROM yauth_users
WHERE ($1::text = '' OR LOWER(email) LIKE '%' || LOWER($1::text) || '%' OR LOWER(COALESCE(display_name, '')) LIKE '%' || LOWER($1::text) || '%');
