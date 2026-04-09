-- Find user by email (case-insensitive).
-- Params: ? email (VARCHAR)
-- Returns: full user row or empty
-- Plugin: core
SELECT * FROM yauth_users WHERE LOWER(email) = LOWER(?);
