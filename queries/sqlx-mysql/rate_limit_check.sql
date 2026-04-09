-- Check rate limit for a key within a time window.
-- Params: ? key (VARCHAR), ? window_secs (INT)
-- Returns: count and window_start, or empty if no record in window
-- Plugin: core
SELECT * FROM yauth_rate_limits WHERE key = ? AND window_start > CURRENT_TIMESTAMP - INTERVAL ? SECOND;
