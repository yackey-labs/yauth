-- Auto-unlock: clear locked_until and locked_reason.
-- Params: $1 id (UUID)
-- Returns: nothing
-- Plugin: account-lockout
UPDATE yauth_account_locks SET locked_until = NULL, locked_reason = NULL, updated_at = NOW() WHERE id = $1;
