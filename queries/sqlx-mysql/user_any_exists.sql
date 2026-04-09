-- Check if any user exists.
-- Params: none
-- Returns: single boolean column
-- Plugin: core
SELECT EXISTS(SELECT 1 FROM yauth_users) AS exists;
