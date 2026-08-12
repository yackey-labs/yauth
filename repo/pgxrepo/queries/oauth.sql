-- name: CreateOAuthState :exec
INSERT INTO yauth_oauth_states (state, provider, redirect_url, expires_at, created_at)
VALUES ($1, $2, $3, $4, $5);

-- name: GetAndDeleteOAuthState :one
DELETE FROM yauth_oauth_states WHERE state = $1 AND expires_at > NOW() RETURNING *;

-- name: GetOAuthAccountByProviderAndProviderUserID :one
SELECT * FROM yauth_oauth_accounts
WHERE provider = $1 AND provider_user_id = $2
LIMIT 1;

-- name: GetOAuthAccountsByUserID :many
SELECT * FROM yauth_oauth_accounts WHERE user_id = $1 ORDER BY created_at ASC;

-- name: GetOAuthAccountByUserAndProvider :one
SELECT * FROM yauth_oauth_accounts WHERE user_id = $1 AND provider = $2 LIMIT 1;

-- name: CreateOAuthAccount :exec
INSERT INTO yauth_oauth_accounts (id, user_id, provider, provider_user_id, access_token_enc, refresh_token_enc, created_at, expires_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9);

-- name: UpdateOAuthAccountTokens :execrows
UPDATE yauth_oauth_accounts
SET access_token_enc = $2, refresh_token_enc = $3, expires_at = $4, updated_at = $5
WHERE id = $1;

-- name: DeleteOAuthAccount :execrows
DELETE FROM yauth_oauth_accounts WHERE id = $1;

-- name: CreateRefreshToken :exec
INSERT INTO yauth_refresh_tokens (id, user_id, token_hash, family_id, client_id, expires_at, revoked, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8);

-- name: GetRefreshTokenByHash :one
SELECT * FROM yauth_refresh_tokens WHERE token_hash = $1 LIMIT 1;

-- name: RevokeRefreshToken :execrows
UPDATE yauth_refresh_tokens SET revoked = true WHERE id = $1;

-- name: RevokeRefreshTokenFamily :execrows
UPDATE yauth_refresh_tokens SET revoked = true WHERE family_id = $1 AND revoked = false;
