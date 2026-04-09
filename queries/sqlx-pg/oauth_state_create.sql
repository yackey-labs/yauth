-- Create an OAuth CSRF state token.
-- Params: $1 state (VARCHAR), $2 provider (VARCHAR), $3 redirect_url (VARCHAR, nullable), $4 expires_at (TIMESTAMPTZ)
-- Returns: nothing
-- Plugin: oauth
INSERT INTO yauth_oauth_states (state, provider, redirect_url, expires_at, created_at)
VALUES ($1, $2, $3, $4, NOW());
