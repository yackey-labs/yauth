-- Find session by ID.
-- Params: ? id (TEXT)
-- Returns: session row or empty
-- Plugin: core
SELECT * FROM yauth_sessions WHERE id = ?;
