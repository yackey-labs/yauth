-- Create a new user.
-- Params: $1 id (UUID), $2 email (VARCHAR), $3 display_name (VARCHAR, nullable)
-- Returns: created user row
-- Plugin: core
INSERT INTO yauth_users (id, email, display_name, email_verified, role, banned, created_at, updated_at)
VALUES ($1, $2, $3, false, 'user', false, NOW(), NOW())
RETURNING *;
