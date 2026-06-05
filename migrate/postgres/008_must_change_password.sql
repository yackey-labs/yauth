-- +goose Up
-- +goose StatementBegin
-- must_change_password marks an account whose credential was provisioned
-- out-of-band (admin/seed/bootstrap) and therefore MUST be rotated by the
-- user before the credential is trusted for normal use — the Jenkins/GitLab
-- "forced password change on first sign-in" primitive. yauth surfaces this on
-- the resolved AuthUser and clears it automatically when the user changes or
-- resets their password; enforcement (gate/redirect) is the consuming app's
-- choice. Existing rows default to false (no forced change).
ALTER TABLE yauth_users ADD COLUMN IF NOT EXISTS must_change_password boolean NOT NULL DEFAULT false;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE yauth_users DROP COLUMN IF EXISTS must_change_password;
-- +goose StatementEnd
