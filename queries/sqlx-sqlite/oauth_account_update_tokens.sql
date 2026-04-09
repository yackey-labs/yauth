-- Update OAuth tokens.
-- Params: ? access_token_enc (VARCHAR, nullable), ? refresh_token_enc (VARCHAR, nullable), ? expires_at (TIMESTAMPTZ, nullable), ? id (TEXT)
-- Returns: nothing
-- Plugin: oauth
UPDATE yauth_oauth_accounts
SET access_token_enc = ?, refresh_token_enc = ?, expires_at = ?, updated_at = datetime('now')
WHERE id = ?;
