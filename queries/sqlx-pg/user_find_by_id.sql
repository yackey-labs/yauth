-- Find user by ID.
-- Params: $1 id (UUID)
-- Returns: full user row or empty
-- Plugin: core
SELECT * FROM yauth_users WHERE id = $1;
