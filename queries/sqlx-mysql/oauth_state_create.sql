-- Create an OAuth CSRF state token.
-- Params: ? state (VARCHAR), ? provider (VARCHAR), ? redirect_url (VARCHAR, nullable), ? expires_at (TIMESTAMPTZ)
-- Returns: nothing
-- Plugin: oauth
INSERT INTO yauth_oauth_states (state, provider, redirect_url, expires_at, created_at)
VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP);
