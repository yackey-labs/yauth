-- Revoke a token (JTI).
-- Params: $1 key (VARCHAR), $2 expires_at (TIMESTAMPTZ)
-- Returns: nothing
-- Plugin: core
INSERT INTO yauth_revocations (key, expires_at) VALUES ($1, $2)
ON CONFLICT (key) DO NOTHING;
