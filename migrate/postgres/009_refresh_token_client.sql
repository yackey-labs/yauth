-- +goose Up
-- +goose StatementBegin
-- client_id is the refresh-token issuer discriminator.
--
-- yauth_refresh_tokens is written by TWO independent issuers — the bearer
-- plugin (first-party email+password logins) and the oauth2server plugin
-- (per-client OAuth2/OIDC grants) — and both redeemed rows by bare token
-- hash. Nothing on the row said who the token had been minted for, so a
-- refresh token handed to a third-party OAuth2 client under a read-only
-- "openid" consent could be posted to the first-party /token/refresh and
-- came back as a full first-party access token; and a first-party token
-- could be redeemed at /oauth/token by ANY registered public client.
--
-- Semantics:
--   NULL     → first-party (bearer plugin). Redeemable only at /token/refresh.
--   non-NULL → the OAuth2 client the token was issued to. Redeemable only at
--              /oauth/token, and only when the authenticated client matches.
--
-- Backwards compatibility: existing rows default to NULL, i.e. first-party,
-- so refresh tokens already held by mobile/API clients keep working across
-- the deploy. The residue is that an OAuth2-issued token minted BEFORE this
-- migration is also indistinguishable from a first-party one (its client was
-- never recorded) and stays redeemable at /token/refresh until it expires;
-- it is, however, no longer redeemable at /oauth/token, so third-party
-- clients re-run the authorization-code flow. Deployments that want the
-- window closed immediately can revoke outstanding tokens after migrating:
--   UPDATE yauth_refresh_tokens SET revoked = true WHERE revoked = false;
ALTER TABLE yauth_refresh_tokens ADD COLUMN IF NOT EXISTS client_id TEXT;
CREATE INDEX IF NOT EXISTS idx_yauth_refresh_tokens_client_id ON yauth_refresh_tokens (client_id);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_yauth_refresh_tokens_client_id;
ALTER TABLE yauth_refresh_tokens DROP COLUMN IF EXISTS client_id;
-- +goose StatementEnd
