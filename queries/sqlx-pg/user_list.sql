-- List users with optional search filter.
-- Params: $1 search (VARCHAR, use '%' for no filter), $2 limit (INT), $3 offset (INT)
-- Returns: matching user rows
-- Plugin: core
SELECT * FROM yauth_users
WHERE LOWER(email) LIKE LOWER($1) OR LOWER(display_name) LIKE LOWER($1)
ORDER BY created_at DESC
LIMIT $2 OFFSET $3;
