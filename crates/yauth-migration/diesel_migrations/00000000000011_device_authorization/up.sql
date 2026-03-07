CREATE TABLE IF NOT EXISTS yauth_device_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_code_hash VARCHAR UNIQUE NOT NULL,
    user_code VARCHAR UNIQUE NOT NULL,
    client_id VARCHAR NOT NULL,
    scopes JSONB,
    user_id UUID REFERENCES yauth_users(id) ON DELETE CASCADE,
    status VARCHAR NOT NULL DEFAULT 'pending',
    interval INT NOT NULL DEFAULT 5,
    expires_at TIMESTAMPTZ NOT NULL,
    last_polled_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
