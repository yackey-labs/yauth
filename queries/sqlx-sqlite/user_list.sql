-- List users with optional search filter.
-- Params: ? search (VARCHAR, use '%' for no filter), ? limit (INT), ? offset (INT)
-- Returns: matching user rows
-- Plugin: core
SELECT * FROM yauth_users
WHERE LOWER(email) LIKE LOWER(?) OR LOWER(display_name) LIKE LOWER(?)
ORDER BY created_at DESC
LIMIT ? OFFSET ?;
