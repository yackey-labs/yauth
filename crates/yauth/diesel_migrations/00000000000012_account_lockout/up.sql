CREATE TABLE IF NOT EXISTS yauth_account_locks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES yauth_users(id) ON DELETE CASCADE UNIQUE,
    failed_count INT NOT NULL DEFAULT 0,
    locked_until TIMESTAMPTZ,
    lock_count INT NOT NULL DEFAULT 0,
    locked_reason VARCHAR,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS yauth_unlock_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES yauth_users(id) ON DELETE CASCADE,
    token_hash VARCHAR UNIQUE NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
