-- +goose Up
-- +goose StatementBegin
-- OIDC logout support (RP-Initiated Logout 1.0 + Back-Channel Logout 1.0).
-- MySQL TEXT columns cannot carry a DEFAULT, so post_logout_redirect_uris is
-- nullable; the application always writes a concrete JSON array ('[]' when
-- empty) on insert and coalesces NULL→'[]' on read.
ALTER TABLE yauth_oauth2_clients ADD COLUMN post_logout_redirect_uris MEDIUMTEXT;
ALTER TABLE yauth_oauth2_clients ADD COLUMN backchannel_logout_uri TEXT;
ALTER TABLE yauth_oauth2_clients ADD COLUMN backchannel_logout_session_required TINYINT(1) NOT NULL DEFAULT 0;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE yauth_oauth2_clients DROP COLUMN backchannel_logout_session_required;
ALTER TABLE yauth_oauth2_clients DROP COLUMN backchannel_logout_uri;
ALTER TABLE yauth_oauth2_clients DROP COLUMN post_logout_redirect_uris;
-- +goose StatementEnd
