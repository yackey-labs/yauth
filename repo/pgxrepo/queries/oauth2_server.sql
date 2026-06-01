-- name: CreateOAuth2Client :exec
INSERT INTO yauth_oauth2_clients (id, client_id, client_secret_hash, redirect_uris, client_name, grant_types, scopes, is_public, created_at, token_endpoint_auth_method, public_key_pem, jwks_uri, banned_at, banned_reason)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14);

-- name: GetOAuth2ClientByClientID :one
SELECT * FROM yauth_oauth2_clients WHERE client_id = $1 LIMIT 1;

-- name: SetOAuth2ClientBanned :one
UPDATE yauth_oauth2_clients
SET banned_at = $2, banned_reason = $3
WHERE client_id = $1
RETURNING *;

-- name: RotateOAuth2ClientPublicKey :execrows
UPDATE yauth_oauth2_clients SET public_key_pem = $2 WHERE client_id = $1;

-- name: ListBannedOAuth2Clients :many
SELECT * FROM yauth_oauth2_clients WHERE banned_at IS NOT NULL ORDER BY banned_at DESC;

-- name: SetOAuth2ClientEnforceGroupAssignment :execrows
UPDATE yauth_oauth2_clients SET enforce_group_assignment = $2 WHERE client_id = $1;

-- name: CreateAuthorizationCode :exec
INSERT INTO yauth_authorization_codes (id, code_hash, client_id, user_id, scopes, redirect_uri, code_challenge, code_challenge_method, expires_at, used, nonce, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12);

-- name: GetAuthorizationCodeByHash :one
SELECT * FROM yauth_authorization_codes WHERE code_hash = $1 AND used = false LIMIT 1;

-- name: MarkAuthorizationCodeUsed :execrows
UPDATE yauth_authorization_codes SET used = true WHERE id = $1 AND used = false;

-- name: ConsumeAuthorizationCode :one
UPDATE yauth_authorization_codes
SET used = true
WHERE code_hash = $1 AND used = false AND expires_at > NOW()
RETURNING *;

-- name: CreateConsent :exec
INSERT INTO yauth_consents (id, user_id, client_id, scopes, created_at)
VALUES ($1, $2, $3, $4, $5);

-- name: GetConsentByUserAndClient :one
SELECT * FROM yauth_consents WHERE user_id = $1 AND client_id = $2 LIMIT 1;

-- name: UpdateConsentScopes :execrows
UPDATE yauth_consents SET scopes = $2 WHERE id = $1;

-- name: CreateDeviceCode :exec
INSERT INTO yauth_device_codes (id, device_code_hash, user_code, client_id, scopes, user_id, status, interval, expires_at, last_polled_at, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11);

-- name: GetDeviceCodeByUserCodePending :one
SELECT * FROM yauth_device_codes
WHERE user_code = $1 AND status = 'pending' AND expires_at > NOW()
LIMIT 1;

-- name: GetDeviceCodeByDeviceCodeHash :one
SELECT * FROM yauth_device_codes WHERE device_code_hash = $1 LIMIT 1;

-- name: UpdateDeviceCodeStatus :execrows
UPDATE yauth_device_codes SET status = $2, user_id = $3 WHERE id = $1;

-- name: UpdateDeviceCodeLastPolled :execrows
UPDATE yauth_device_codes SET last_polled_at = $2 WHERE id = $1;

-- name: UpdateDeviceCodeInterval :execrows
UPDATE yauth_device_codes SET interval = $2 WHERE id = $1;

-- name: CreateOIDCNonce :exec
INSERT INTO yauth_oidc_nonces (id, nonce_hash, authorization_code_id, created_at)
VALUES ($1, $2, $3, $4);

-- name: GetOIDCNonceByHash :one
SELECT * FROM yauth_oidc_nonces WHERE nonce_hash = $1 LIMIT 1;

-- name: DeleteOIDCNonce :execrows
DELETE FROM yauth_oidc_nonces WHERE id = $1;
