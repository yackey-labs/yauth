-- Store a challenge with TTL.
-- Params: ? key (VARCHAR), ? value (JSON), ? expires_at (TIMESTAMPTZ)
-- Returns: nothing
-- Plugin: core
INSERT INTO yauth_challenges (`key`, value, expires_at) VALUES (?, ?, ?)
ON DUPLICATE KEY UPDATE value = VALUES(value), expires_at = VALUES(expires_at);
