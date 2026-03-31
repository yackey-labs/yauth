CREATE TABLE IF NOT EXISTS yauth_api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES yauth_users(id) ON DELETE CASCADE,
    key_prefix VARCHAR(12) UNIQUE NOT NULL,
    key_hash VARCHAR(64) NOT NULL,
    name VARCHAR NOT NULL,
    scopes JSONB,
    last_used_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
