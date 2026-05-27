-- name: CreateMagicLink :exec
INSERT INTO yauth_magic_links (id, email, token_hash, expires_at, used, created_at)
VALUES ($1, $2, $3, $4, false, $5);

-- name: GetUnusedMagicLinkByTokenHash :one
SELECT * FROM yauth_magic_links WHERE token_hash = $1 AND used = false LIMIT 1;

-- name: MarkMagicLinkUsed :execrows
UPDATE yauth_magic_links SET used = true WHERE id = $1 AND used = false;

-- name: DeleteMagicLink :execrows
DELETE FROM yauth_magic_links WHERE id = $1;

-- name: DeleteUnusedMagicLinksForEmail :execrows
DELETE FROM yauth_magic_links WHERE email = $1 AND used = false;

-- name: ConsumeMagicLink :one
UPDATE yauth_magic_links
SET used = true
WHERE token_hash = $1 AND used = false AND expires_at > NOW()
RETURNING *;
