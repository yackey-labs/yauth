-- Update OAuth tokens.
-- Params: $1 access_token_enc (VARCHAR, nullable), $2 refresh_token_enc (VARCHAR, nullable), $3 expires_at (TIMESTAMPTZ, nullable), $4 id (UUID)
-- Returns: nothing
-- Plugin: oauth
UPDATE yauth_oauth_accounts
SET access_token_enc = $1, refresh_token_enc = $2, expires_at = $3, updated_at = NOW()
WHERE id = $4;
