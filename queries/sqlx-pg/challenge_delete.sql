-- Delete a challenge by key.
-- Params: $1 key (VARCHAR)
-- Returns: nothing
-- Plugin: core
DELETE FROM yauth_challenges WHERE key = $1;
