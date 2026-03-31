-- Revert jsonb columns back to json.
-- Note: this is safe but rarely needed — jsonb is strictly better.

ALTER TABLE yauth_oauth2_clients
    ALTER COLUMN redirect_uris TYPE json USING redirect_uris::json,
    ALTER COLUMN grant_types   TYPE json USING grant_types::json,
    ALTER COLUMN scopes        TYPE json USING scopes::json;

ALTER TABLE yauth_authorization_codes
    ALTER COLUMN scopes TYPE json USING scopes::json;

ALTER TABLE yauth_consents
    ALTER COLUMN scopes TYPE json USING scopes::json;

ALTER TABLE yauth_device_codes
    ALTER COLUMN scopes TYPE json USING scopes::json;

ALTER TABLE yauth_webauthn_credentials
    ALTER COLUMN credential TYPE json USING credential::json;

ALTER TABLE yauth_audit_log
    ALTER COLUMN metadata TYPE json USING metadata::json;
