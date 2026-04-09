-- Delete a user. Cascades to all related entities.
-- Params: ? id (TEXT)
-- Returns: nothing
-- Plugin: core
DELETE FROM yauth_users WHERE id = ?;
