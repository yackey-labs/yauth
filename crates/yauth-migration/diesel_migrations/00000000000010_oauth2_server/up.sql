CREATE TABLE IF NOT EXISTS yauth_oauth2_clients (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id VARCHAR UNIQUE NOT NULL,
    client_secret_hash VARCHAR,
    redirect_uris JSONB NOT NULL,
    client_name VARCHAR,
    grant_types JSONB NOT NULL,
    scopes JSONB,
    is_public BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS yauth_authorization_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code_hash VARCHAR UNIQUE NOT NULL,
    client_id VARCHAR NOT NULL,
    user_id UUID REFERENCES yauth_users(id) ON DELETE CASCADE,
    scopes JSONB,
    redirect_uri VARCHAR NOT NULL,
    code_challenge VARCHAR NOT NULL,
    code_challenge_method VARCHAR NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used BOOLEAN NOT NULL DEFAULT false,
    nonce VARCHAR,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS yauth_consents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES yauth_users(id) ON DELETE CASCADE,
    client_id VARCHAR NOT NULL,
    scopes JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
