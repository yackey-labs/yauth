-- name: UpsertChallenge :exec
INSERT INTO yauth_challenges (key, value, expires_at)
VALUES ($1, $2, $3)
ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, expires_at = EXCLUDED.expires_at;

-- name: GetChallenge :one
SELECT * FROM yauth_challenges WHERE key = $1 LIMIT 1;

-- name: DeleteChallenge :execrows
DELETE FROM yauth_challenges WHERE key = $1;

-- name: UpsertRateLimit :one
INSERT INTO yauth_rate_limits (key, count, window_start)
VALUES ($1, 1, $2)
ON CONFLICT (key) DO UPDATE
    SET count = CASE
        WHEN yauth_rate_limits.window_start + ($3 * INTERVAL '1 microsecond') <= NOW()
        THEN 1
        ELSE yauth_rate_limits.count + 1
    END,
    window_start = CASE
        WHEN yauth_rate_limits.window_start + ($3 * INTERVAL '1 microsecond') <= NOW()
        THEN $2
        ELSE yauth_rate_limits.window_start
    END
RETURNING *;

-- name: GetRateLimit :one
SELECT * FROM yauth_rate_limits WHERE key = $1 LIMIT 1;

-- name: RevokeToken :exec
INSERT INTO yauth_revocations (key, expires_at)
VALUES ($1, $2)
ON CONFLICT (key) DO UPDATE SET expires_at = GREATEST(EXCLUDED.expires_at, yauth_revocations.expires_at);

-- name: GetRevocation :one
SELECT * FROM yauth_revocations WHERE key = $1 LIMIT 1;

-- name: DeleteExpiredRevocations :execrows
DELETE FROM yauth_revocations WHERE expires_at <= $1;
