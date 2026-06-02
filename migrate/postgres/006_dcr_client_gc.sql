-- +goose Up
-- +goose StatementBegin
-- Signals for garbage-collecting stale dynamically-registered (DCR) OAuth2
-- clients. dynamically_registered scopes the sweep to self-registered clients
-- only (never admin-provisioned ones); last_used_at is the activity timestamp
-- (NULL → fall back to created_at) stamped on token-endpoint use, so a client
-- in active use is never swept regardless of age.
ALTER TABLE yauth_oauth2_clients ADD COLUMN IF NOT EXISTS dynamically_registered BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE yauth_oauth2_clients ADD COLUMN IF NOT EXISTS last_used_at TIMESTAMPTZ;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE yauth_oauth2_clients DROP COLUMN IF EXISTS last_used_at;
ALTER TABLE yauth_oauth2_clients DROP COLUMN IF EXISTS dynamically_registered;
-- +goose StatementEnd
