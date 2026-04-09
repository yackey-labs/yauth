-- Find account lock state for a user.
-- Params: ? user_id (TEXT)
-- Returns: lock row or empty
-- Plugin: account-lockout
SELECT * FROM yauth_account_locks WHERE user_id = ?;
