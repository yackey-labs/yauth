-- Store a challenge with TTL.
-- Params: $1 key (VARCHAR), $2 value (JSON), $3 expires_at (TIMESTAMPTZ)
-- Returns: nothing
-- Plugin: core
INSERT INTO yauth_challenges (key, value, expires_at) VALUES ($1, $2, $3)
ON CONFLICT (key) DO UPDATE SET value = $2, expires_at = $3;
