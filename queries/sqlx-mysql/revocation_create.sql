-- Revoke a token (JTI).
-- Params: ? key (VARCHAR), ? expires_at (TIMESTAMPTZ)
-- Returns: nothing
-- Plugin: core
INSERT IGNORE INTO yauth_revocations (`key`, expires_at) VALUES (?, ?);
