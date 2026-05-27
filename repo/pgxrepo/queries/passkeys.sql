-- name: GetPasskeysByUserID :many
SELECT * FROM yauth_webauthn_credentials WHERE user_id = $1 ORDER BY created_at ASC;

-- name: GetPasskeyByIDAndUser :one
SELECT * FROM yauth_webauthn_credentials WHERE id = $1 AND user_id = $2 LIMIT 1;

-- name: CreatePasskey :exec
INSERT INTO yauth_webauthn_credentials (id, user_id, name, aaguid, device_name, credential, created_at, last_used_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8);

-- name: UpdatePasskeyLastUsed :execrows
UPDATE yauth_webauthn_credentials SET last_used_at = $2 WHERE id = $1;

-- name: DeletePasskey :execrows
DELETE FROM yauth_webauthn_credentials WHERE id = $1;

-- name: GetTOTPByUserID :one
SELECT * FROM yauth_totp_secrets
WHERE user_id = $1
AND ($2::bool = false OR verified = true)
LIMIT 1;

-- name: CreateTOTP :exec
INSERT INTO yauth_totp_secrets (id, user_id, encrypted_secret, verified, created_at)
VALUES ($1, $2, $3, $4, $5);

-- name: MarkTOTPVerified :execrows
UPDATE yauth_totp_secrets SET verified = true WHERE id = $1;

-- name: DeleteTOTPForUser :execrows
DELETE FROM yauth_totp_secrets
WHERE user_id = $1
AND ($2::bool = false OR verified = true);

-- name: GetUnusedBackupCodesByUserID :many
SELECT * FROM yauth_backup_codes WHERE user_id = $1 AND used = false ORDER BY created_at ASC;

-- name: CreateBackupCode :exec
INSERT INTO yauth_backup_codes (id, user_id, code_hash, used, created_at)
VALUES ($1, $2, $3, $4, $5);

-- name: MarkBackupCodeUsed :execrows
UPDATE yauth_backup_codes SET used = true WHERE id = $1 AND used = false;

-- name: DeleteAllBackupCodesForUser :execrows
DELETE FROM yauth_backup_codes WHERE user_id = $1;
