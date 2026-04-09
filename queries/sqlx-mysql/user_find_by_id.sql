-- Find user by ID.
-- Params: ? id (CHAR(36))
-- Returns: full user row or empty
-- Plugin: core
SELECT * FROM yauth_users WHERE id = ?;
