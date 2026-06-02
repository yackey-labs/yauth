-- +goose Up
-- +goose StatementBegin
-- OIDC logout support (RP-Initiated Logout 1.0 + Back-Channel Logout 1.0).
ALTER TABLE yauth_oauth2_clients ADD COLUMN post_logout_redirect_uris TEXT NOT NULL DEFAULT '[]';
ALTER TABLE yauth_oauth2_clients ADD COLUMN backchannel_logout_uri TEXT;
ALTER TABLE yauth_oauth2_clients ADD COLUMN backchannel_logout_session_required INTEGER NOT NULL DEFAULT 0;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE yauth_oauth2_clients DROP COLUMN backchannel_logout_session_required;
ALTER TABLE yauth_oauth2_clients DROP COLUMN backchannel_logout_uri;
ALTER TABLE yauth_oauth2_clients DROP COLUMN post_logout_redirect_uris;
-- +goose StatementEnd
