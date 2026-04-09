-- Delete a user. Cascades to all related entities.
-- Params: ? id (CHAR(36))
-- Returns: nothing
-- Plugin: core
DELETE FROM yauth_users WHERE id = ?;
