-- Find account lock state for a user.
-- Params: $1 user_id (UUID)
-- Returns: lock row or empty
-- Plugin: account-lockout
SELECT * FROM yauth_account_locks WHERE user_id = $1;
