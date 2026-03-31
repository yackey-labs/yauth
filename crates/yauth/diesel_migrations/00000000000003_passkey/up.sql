CREATE TABLE IF NOT EXISTS yauth_webauthn_credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES yauth_users(id) ON DELETE CASCADE,
    name VARCHAR NOT NULL,
    aaguid VARCHAR,
    device_name VARCHAR,
    credential JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ
);
