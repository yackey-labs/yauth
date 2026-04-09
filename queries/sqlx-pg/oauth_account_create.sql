-- Link an OAuth account to a user.
-- Params: $1 id (UUID), $2 user_id (UUID), $3 provider (VARCHAR), $4 provider_user_id (VARCHAR), $5 access_token_enc (VARCHAR, nullable), $6 refresh_token_enc (VARCHAR, nullable), $7 expires_at (TIMESTAMPTZ, nullable)
-- Returns: nothing
-- Plugin: oauth
INSERT INTO yauth_oauth_accounts (id, user_id, provider, provider_user_id, access_token_enc, refresh_token_enc, expires_at, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW());
