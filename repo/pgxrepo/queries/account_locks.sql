-- name: GetAccountLockByUserID :one
SELECT * FROM yauth_account_locks WHERE user_id = $1 LIMIT 1;

-- name: CreateAccountLock :one
INSERT INTO yauth_account_locks (id, user_id, failed_count, locked_until, lock_count, locked_reason, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING *;

-- Returns the POST-increment count so the caller can compare it against the
-- lockout threshold without a second read. Deciding from a separately-read
-- count let concurrent failures all observe the same stale value, so the
-- threshold was never crossed and the account never locked.
-- name: IncrementAccountLockFailedCount :one
UPDATE yauth_account_locks SET failed_count = failed_count + 1, updated_at = $2 WHERE id = $1
RETURNING failed_count;

-- name: SetAccountLockState :execrows
UPDATE yauth_account_locks
SET locked_reason = $2, lock_count = $3, locked_until = $4, updated_at = $5
WHERE id = $1;

-- name: ResetAccountLockFailedCount :execrows
UPDATE yauth_account_locks SET failed_count = 0, updated_at = $2 WHERE id = $1;

-- name: AutoUnlockAccount :execrows
UPDATE yauth_account_locks SET locked_until = NULL, locked_reason = NULL, updated_at = $2 WHERE id = $1;

-- name: CreateUnlockToken :exec
INSERT INTO yauth_unlock_tokens (id, user_id, token_hash, expires_at, created_at)
VALUES ($1, $2, $3, $4, $5);

-- name: GetUnlockTokenByHash :one
SELECT * FROM yauth_unlock_tokens WHERE token_hash = $1 LIMIT 1;

-- name: ConsumeUnlockToken :one
DELETE FROM yauth_unlock_tokens
WHERE token_hash = $1 AND expires_at > NOW()
RETURNING *;

-- name: DeleteUnlockTokenByHash :execrows
DELETE FROM yauth_unlock_tokens WHERE token_hash = $1;

-- name: DeleteUnlockToken :execrows
DELETE FROM yauth_unlock_tokens WHERE id = $1;

-- name: DeleteAllUnlockTokensForUser :execrows
DELETE FROM yauth_unlock_tokens WHERE user_id = $1;
