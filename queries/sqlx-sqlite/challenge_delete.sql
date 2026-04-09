-- Delete a challenge by key.
-- Params: ? key (VARCHAR)
-- Returns: nothing
-- Plugin: core
DELETE FROM yauth_challenges WHERE key = ?;
