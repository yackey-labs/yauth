-- Create a new user.
-- Params: ? id (TEXT), ? email (VARCHAR), ? display_name (VARCHAR, nullable)
-- Returns: created user row
-- Plugin: core
INSERT INTO yauth_users (id, email, display_name, email_verified, role, banned, created_at, updated_at)
VALUES (?, ?, ?, false, 'user', false, datetime('now'), datetime('now'))
RETURNING *;
