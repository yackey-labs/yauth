-- Increment or create a rate limit counter.
-- Params: ? key (VARCHAR)
-- Returns: nothing
-- Plugin: core
INSERT INTO yauth_rate_limits (`key`, count, window_start) VALUES (?, 1, CURRENT_TIMESTAMP)
ON DUPLICATE KEY UPDATE count = count + 1;
