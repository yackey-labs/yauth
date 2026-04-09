-- Increment failed login count.
-- Params: $1 id (UUID)
-- Returns: nothing
-- Plugin: account-lockout
UPDATE yauth_account_locks SET failed_count = failed_count + 1, updated_at = NOW() WHERE id = $1;
