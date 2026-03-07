CREATE TABLE IF NOT EXISTS yauth_oidc_nonces (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    nonce_hash VARCHAR UNIQUE NOT NULL,
    authorization_code_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
