-- Link an OAuth account to a user.
-- Params: ? id (TEXT), ? user_id (TEXT), ? provider (VARCHAR), ? provider_user_id (VARCHAR), ? access_token_enc (VARCHAR, nullable), ? refresh_token_enc (VARCHAR, nullable), ? expires_at (TIMESTAMPTZ, nullable)
-- Returns: nothing
-- Plugin: oauth
INSERT INTO yauth_oauth_accounts (id, user_id, provider, provider_user_id, access_token_enc, refresh_token_enc, expires_at, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'));
