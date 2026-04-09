-- Find session by ID.
-- Params: ? id (CHAR(36))
-- Returns: session row or empty
-- Plugin: core
SELECT * FROM yauth_sessions WHERE id = ?;
