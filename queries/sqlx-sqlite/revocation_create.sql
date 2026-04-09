-- Revoke a token (JTI).
-- Params: ? key (VARCHAR), ? expires_at (TIMESTAMPTZ)
-- Returns: nothing
-- Plugin: core
INSERT OR IGNORE INTO yauth_revocations (key, expires_at) VALUES (?, ?);
