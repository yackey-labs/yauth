CREATE TABLE IF NOT EXISTS yauth_users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR NOT NULL UNIQUE,
    display_name VARCHAR,
    email_verified BOOLEAN NOT NULL DEFAULT false,
    role VARCHAR NOT NULL DEFAULT 'user',
    banned BOOLEAN NOT NULL DEFAULT false,
    banned_reason VARCHAR,
    banned_until TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS yauth_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES yauth_users(id) ON DELETE CASCADE,
    token_hash VARCHAR(64) NOT NULL UNIQUE,
    ip_address VARCHAR,
    user_agent VARCHAR,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS yauth_audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES yauth_users(id) ON DELETE SET NULL,
    event_type VARCHAR NOT NULL,
    metadata JSONB,
    ip_address VARCHAR,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
