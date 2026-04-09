-- Lock an account.
-- Params: $1 locked_until (TIMESTAMPTZ, nullable), $2 locked_reason (VARCHAR, nullable), $3 lock_count (INT), $4 id (UUID)
-- Returns: nothing
-- Plugin: account-lockout
UPDATE yauth_account_locks SET locked_until = $1, locked_reason = $2, lock_count = $3, updated_at = NOW() WHERE id = $4;
