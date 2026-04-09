-- Delete a user. Cascades to all related entities.
-- Params: $1 id (UUID)
-- Returns: nothing
-- Plugin: core
DELETE FROM yauth_users WHERE id = $1;
