CREATE TABLE IF NOT EXISTS yauth_webhooks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    url VARCHAR NOT NULL,
    secret VARCHAR NOT NULL,
    events JSONB NOT NULL,
    active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS yauth_webhook_deliveries (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    webhook_id UUID REFERENCES yauth_webhooks(id) ON DELETE CASCADE,
    event_type VARCHAR NOT NULL,
    payload JSONB NOT NULL,
    status_code SMALLINT,
    response_body TEXT,
    success BOOLEAN NOT NULL DEFAULT false,
    attempt INT NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
