-- +goose Up
-- +goose StatementBegin
-- OIDC logout support (RP-Initiated Logout 1.0 + Back-Channel Logout 1.0).
--   post_logout_redirect_uris: JSON array of URIs the client may be redirected
--     to after end_session (validated to prevent open redirect).
--   backchannel_logout_uri: the client's Back-Channel Logout endpoint; when set,
--     the OP POSTs a signed logout_token there when the user's session ends.
--   backchannel_logout_session_required: client wants a `sid` claim in the
--     logout_token (OIDC BCL §2.4).
ALTER TABLE yauth_oauth2_clients ADD COLUMN IF NOT EXISTS post_logout_redirect_uris TEXT NOT NULL DEFAULT '[]';
ALTER TABLE yauth_oauth2_clients ADD COLUMN IF NOT EXISTS backchannel_logout_uri TEXT;
ALTER TABLE yauth_oauth2_clients ADD COLUMN IF NOT EXISTS backchannel_logout_session_required BOOLEAN NOT NULL DEFAULT FALSE;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE yauth_oauth2_clients DROP COLUMN IF EXISTS backchannel_logout_session_required;
ALTER TABLE yauth_oauth2_clients DROP COLUMN IF EXISTS backchannel_logout_uri;
ALTER TABLE yauth_oauth2_clients DROP COLUMN IF EXISTS post_logout_redirect_uris;
-- +goose StatementEnd
