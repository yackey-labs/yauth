-- Fix json columns that should be jsonb.
--
-- The Diesel schema defines these as Jsonb, but the tables were originally
-- created by SeaORM migrations which used the json type. The CREATE TABLE IF
-- NOT EXISTS in the Diesel migrations left the old json columns in place.
-- Diesel's Jsonb deserializer expects a version byte prefix (0x01) that json
-- columns do not have, causing "Unsupported JSONB encoding version" errors.
--
-- Each ALTER TABLE is wrapped in a DO $$ block so this migration is safe to
-- run multiple times (idempotent). Converting json -> jsonb is lossless.

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name  = 'yauth_oauth2_clients'
          AND column_name = 'redirect_uris'
          AND data_type   = 'json'
    ) THEN
        ALTER TABLE yauth_oauth2_clients
            ALTER COLUMN redirect_uris TYPE jsonb USING redirect_uris::jsonb,
            ALTER COLUMN grant_types   TYPE jsonb USING grant_types::jsonb,
            ALTER COLUMN scopes        TYPE jsonb USING scopes::jsonb;
    END IF;
END $$;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name  = 'yauth_authorization_codes'
          AND column_name = 'scopes'
          AND data_type   = 'json'
    ) THEN
        ALTER TABLE yauth_authorization_codes
            ALTER COLUMN scopes TYPE jsonb USING scopes::jsonb;
    END IF;
END $$;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name  = 'yauth_consents'
          AND column_name = 'scopes'
          AND data_type   = 'json'
    ) THEN
        ALTER TABLE yauth_consents
            ALTER COLUMN scopes TYPE jsonb USING scopes::jsonb;
    END IF;
END $$;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name  = 'yauth_device_codes'
          AND column_name = 'scopes'
          AND data_type   = 'json'
    ) THEN
        ALTER TABLE yauth_device_codes
            ALTER COLUMN scopes TYPE jsonb USING scopes::jsonb;
    END IF;
END $$;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name  = 'yauth_webauthn_credentials'
          AND column_name = 'credential'
          AND data_type   = 'json'
    ) THEN
        ALTER TABLE yauth_webauthn_credentials
            ALTER COLUMN credential TYPE jsonb USING credential::jsonb;
    END IF;
END $$;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name  = 'yauth_audit_log'
          AND column_name = 'metadata'
          AND data_type   = 'json'
    ) THEN
        ALTER TABLE yauth_audit_log
            ALTER COLUMN metadata TYPE jsonb USING metadata::jsonb;
    END IF;
END $$;
