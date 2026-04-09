-- Find user by ID.
-- Params: ? id (TEXT)
-- Returns: full user row or empty
-- Plugin: core
SELECT * FROM yauth_users WHERE id = ?;
