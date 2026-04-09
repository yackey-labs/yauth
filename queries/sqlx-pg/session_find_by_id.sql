-- Find session by ID.
-- Params: $1 id (UUID)
-- Returns: session row or empty
-- Plugin: core
SELECT * FROM yauth_sessions WHERE id = $1;
