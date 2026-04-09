-- Increment or create a rate limit counter.
-- Params: ? key (VARCHAR)
-- Returns: nothing
-- Plugin: core
INSERT INTO yauth_rate_limits (key, count, window_start) VALUES (?, 1, datetime('now'))
ON CONFLICT (key) DO UPDATE SET count = yauth_rate_limits.count + 1;
