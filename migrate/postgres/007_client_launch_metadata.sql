-- +goose Up
-- +goose StatementBegin
-- Standard OIDC / RFC 7591 client metadata for an app-launcher experience.
-- initiate_login_uri is the OIDC third-party / IdP-initiated login URL (the
-- launch target; MUST be https when set, enforced at the API layer). client_uri
-- is the RFC 7591 client home page; logo_uri is the RFC 7591 logo (tile icon).
-- All three are optional and nullable; existing clients keep NULL.
ALTER TABLE yauth_oauth2_clients ADD COLUMN IF NOT EXISTS initiate_login_uri text;
ALTER TABLE yauth_oauth2_clients ADD COLUMN IF NOT EXISTS client_uri text;
ALTER TABLE yauth_oauth2_clients ADD COLUMN IF NOT EXISTS logo_uri text;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE yauth_oauth2_clients DROP COLUMN IF EXISTS logo_uri;
ALTER TABLE yauth_oauth2_clients DROP COLUMN IF EXISTS client_uri;
ALTER TABLE yauth_oauth2_clients DROP COLUMN IF EXISTS initiate_login_uri;
-- +goose StatementEnd
