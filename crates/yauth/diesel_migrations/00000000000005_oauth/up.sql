CREATE TABLE IF NOT EXISTS yauth_oauth_accounts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES yauth_users(id) ON DELETE CASCADE,
    provider VARCHAR NOT NULL,
    provider_user_id VARCHAR NOT NULL,
    access_token_enc VARCHAR,
    refresh_token_enc VARCHAR,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS yauth_oauth_states (
    state VARCHAR PRIMARY KEY,
    provider VARCHAR NOT NULL,
    redirect_url VARCHAR,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
