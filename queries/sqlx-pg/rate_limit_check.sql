-- Check rate limit for a key within a time window.
-- Params: $1 key (VARCHAR), $2 window_secs (INT)
-- Returns: count and window_start, or empty if no record in window
-- Plugin: core
SELECT * FROM yauth_rate_limits WHERE key = $1 AND window_start > NOW() - $2 * INTERVAL '1 second';
