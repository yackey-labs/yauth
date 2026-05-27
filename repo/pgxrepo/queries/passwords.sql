-- name: UpsertPassword :exec
INSERT INTO yauth_passwords (user_id, password_hash)
VALUES ($1, $2)
ON CONFLICT (user_id) DO UPDATE SET password_hash = EXCLUDED.password_hash;

-- name: GetPasswordByUserID :one
SELECT * FROM yauth_passwords WHERE user_id = $1 LIMIT 1;

-- name: AppendPasswordHistory :exec
INSERT INTO yauth_password_history (id, user_id, password_hash, created_at)
VALUES ($1, $2, $3, $4);

-- name: GetPasswordHistory :many
SELECT * FROM yauth_password_history
WHERE user_id = $1
ORDER BY created_at DESC
LIMIT $2;

-- name: TrimPasswordHistory :execrows
DELETE FROM yauth_password_history
WHERE id IN (
    SELECT ph.id FROM yauth_password_history ph
    WHERE ph.user_id = $1
    ORDER BY ph.created_at DESC
    OFFSET $2
);

-- name: CreateEmailVerification :exec
INSERT INTO yauth_email_verifications (id, user_id, token_hash, expires_at, created_at)
VALUES ($1, $2, $3, $4, $5);

-- name: GetEmailVerificationByTokenHash :one
SELECT * FROM yauth_email_verifications WHERE token_hash = $1 LIMIT 1;

-- name: DeleteEmailVerification :execrows
DELETE FROM yauth_email_verifications WHERE id = $1;

-- name: DeleteEmailVerificationsForUser :execrows
DELETE FROM yauth_email_verifications WHERE user_id = $1;

-- name: CreatePasswordReset :exec
INSERT INTO yauth_password_resets (id, user_id, token_hash, expires_at, created_at)
VALUES ($1, $2, $3, $4, $5);

-- name: GetPasswordResetByTokenHash :one
SELECT * FROM yauth_password_resets WHERE token_hash = $1 LIMIT 1;

-- name: MarkPasswordResetUsed :execrows
UPDATE yauth_password_resets SET used_at = $2 WHERE id = $1 AND used_at IS NULL;

-- name: DeleteUnusedPasswordResetsForUser :execrows
DELETE FROM yauth_password_resets WHERE user_id = $1 AND used_at IS NULL;
