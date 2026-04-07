## 0.8.2 (2026-04-07)

### Fixes

- revert cargo binstall recommendation (no prebuilt binaries available) (#41)

## 0.8.1 (2026-04-07)

### Fixes

- recommend cargo binstall for CLI installation in README

## 0.8.0 (2026-04-06)

### Breaking Changes

- multi-ORM backend suite + migration CLI (#39)

### Fixes

- remove accidentally committed skill workspace files, add to .gitignore
- remove unused raw ORM option from migration CLI
- add version specifiers to inter-crate path dependencies for crates.io publishing
- add inter-crate dependency versions to knope versioned_files

## 0.7.1 (2026-04-05)

### Features

- add MySQL backend to example server, skip email verification without SMTP

## 0.7.0 (2026-04-05)

### Breaking Changes

- add MySQL/MariaDB backend + cross-backend conformance test suite

## 0.6.2 (2026-04-05)

### Fixes

- update README pentest command to unified Rust suite (#38)

## 0.6.1 (2026-04-05)

### Fixes

- update CLAUDE.md pentest references to unified Rust suite (#37)
- regenerate client for 0.6.0 version

## 0.6.0 (2026-04-05)

### Breaking Changes

- rename DieselBackend to DieselPgBackend (#35)
- switch all UUID generation from v4 to v7 (#36)

### Fixes

- remove dead backends/diesel and stores modules, unify pentest suites (#33)

## 0.5.0 (2026-04-05)

### Breaking Changes

- unified repo architecture + stores merged + Redis decorators (#30)

### Features

- declarative schema system + diesel-libsql backend (#27)

## 0.4.0 (2026-04-04)

### Breaking Changes

- The `telemetry` feature no longer depends on `tracing`.
Consumers using `tracing::Span::current()` to interact with yauth spans
must switch to `opentelemetry::Context::current()`.

### Features

- add vue-query example with orval TanStack Query hooks (#24)
- replace tracing with native OpenTelemetry SDK for telemetry (#25)

### Fixes

- address review findings from OTel migration (#26)

## 0.3.1 (2026-04-02)

### Fixes

- regenerate OpenAPI spec during knope release (#21)
- remove examples from knope versioned_files (#22)

## 0.3.0 (2026-04-02)

### Breaking Changes

- replace axfetchum with utoipa + orval for client generation (#17)

### Features

- trait-based sessions + Redis store backend (#19)
- OWASP A09/A10 coverage + security vulnerability fixes (#18)

### Fixes

- exclude test files from yauth-shared and yauth-client packages (#15)

## 0.2.5 (2026-03-24)

### Fixes

- install Node.js LTS and update npm for OIDC trusted publishing
- add repository field to all npm packages and reconcile v0.2.5

## 0.2.4 (2026-03-24)

### Fixes

- document partial release recovery process in CLAUDE.md

## 0.2.3 (2026-03-24)

### Fixes

- document npm publish uses npm CLI for OIDC trusted publishing

## 0.2.2 (2026-03-24)

### Fixes

- clean up 0.2.1 release notes
- switch npm publish from bun to npm CLI for OIDC trusted publishing support

## 0.2.1 (2026-03-24)

### Features

- add Vue 3 UI package (@yackey-labs/yauth-ui-vue)

### Fixes

- skip auth checks in auth_middleware if AuthUser already set
- convert json columns to jsonb
- wire migration 016 into runner and make exec_sql dollar-quote aware
- avoid DO blocks — check json columns before ALTER TABLE
- use ALTER TABLE IF EXISTS in migration 016
- use testcontainers for diesel integration tests
- pin testcontainer to postgres:17-alpine
- remove stale SeaORM postgres service from CI
- exclude test files from published npm packages

## 0.2.0 (2026-03-21)

### Breaking Changes

- Remove SeaORM backend entirely — diesel-async is now the only supported database backend
- Remove `seaorm` feature flag from all crates
- Remove `diesel-full` convenience feature (use `full` instead, which now uses diesel-async)
- `diesel-async` is now a default feature — no need for `default-features = false`
- Remove all SeaORM entity files (`crates/yauth-entity/src/*.rs` except diesel module)
- Remove all SeaORM migration files (`crates/yauth-migration/src/m*.rs`)
- Remove `Migrator` struct (use `diesel_migrations::run_migrations()` instead)

### Features

- Make diesel-async the default and only ORM backend
- Simplify feature flags: `full` now enables diesel-async + all plugins
- Add `futures-util` dependency for diesel-async publish compatibility

### Fixes

- Add `futures-util` with `async-await-macro` feature for diesel-async `try_join!` compatibility
- Bump npm package versions to match Cargo versions

## 0.1.59 (2026-03-17)

### Fixes

- rename npm packages to @yackey-labs/yauth-*

## 0.1.58 (2026-03-17)

### Features

- migrate from Forgejo to GitHub

### Fixes

- sync stale bun.lock, regenerate AuthConfigResponse binding, fix biome formatting
- use GitHub-hosted runners for public repo

## 0.1.57 (2026-03-12)

### Features

- add CookieDomainPolicy and expose require_email_verification in config

### Fixes

- use derive(Default) for CookieDomainPolicy to fix clippy CI (#13)

## 0.1.56 (2026-03-12)

### Features

- add CookieDomainPolicy and expose require_email_verification in config

## 0.1.55 (2026-03-12)

### Fixes

- resolve refetch promise after resource signal updates

## 0.1.54 (2026-03-12)

### Fixes

- read form values from FormData at submit time for autofill compatibility
- make provider refetch awaitable to prevent login redirect race

## 0.1.53 (2026-03-11)

### Fixes

- republish with allow_signups and config endpoint (v0.1.51 was stale)
- read form values from FormData at submit time for autofill compatibility

## 0.1.52 (2026-03-09)

### Fixes

- republish with allow_signups and config endpoint (v0.1.51 was stale)

## 0.1.51 (2026-03-09)

### Features

- add pentest coverage for all 6 uncovered plugins (#9)
- security pentest suite (12 vuln test cases) + CI job (#10)
- add global allow_signups flag to YAuthConfig
- add public GET /config endpoint for frontend signup detection
- document AuthConfigResponse for frontend config endpoint

### Fixes

- collapse nested if to satisfy clippy collapsible_if lint
- resolve 5 key pentest vulnerabilities (#11)

## 0.1.50 (2026-03-09)

### Features

- standardize span event names to yauth.* dotted namespace

## 0.1.49 (2026-03-09)

### Features

- add diesel query tracing and align with OTel semconv

## 0.1.48 (2026-03-09)

### Features

- extract W3C traceparent for distributed trace correlation

## 0.1.47 (2026-03-08)

### Features

- adopt Honeycomb-style wide spans for observability

## 0.1.46 (2026-03-08)

### Fixes

- add credential-provider for yackey-cloud registry

## 0.1.45 (2026-03-08)

### Fixes

- use correct token format and clean up release workflow

## 0.1.44 (2026-03-08)

### Fixes

- add registry token for axum-ts-client fetches

## 0.1.43 (2026-03-08)

### Fixes

- use published axum-ts-client 0.1 from registry

## 0.1.42 (2026-03-08)

### Features

- add diesel-async as optional alternative to SeaORM
- add diesel-async support for passkey, bearer, and magic-link plugins
- add diesel-async support for api-key plugin
- add diesel-async support for mfa plugin
- add diesel-async support for account-lockout plugin
- add diesel-async support for oidc plugin
- add diesel-async support for oauth plugin
- add diesel-async support for admin plugin
- add diesel-async support for oauth2-server plugin
- add diesel-async support for webhooks plugin
- add diesel-full feature flag and update CI to test all plugins
- use testcontainers for diesel integration tests

### Fixes

- complete diesel-async support for oauth2-server and bearer plugins
- resolve clippy warnings for diesel-full feature set
- wire up diesel-async generate_id_token_from_fields in oidc plugin
- fix CI failures in TypeScript typecheck and diesel integration tests
- gracefully skip diesel tests when DB and Docker both unavailable
- wait for testcontainer postgres readiness before running tests

## 0.1.41 (2026-03-07)

### Fixes

- add nonce column migration for authorization_codes

## 0.1.40 (2026-03-07)

### Fixes

- resolve TypeScript typecheck errors in client test suite (#7)

## 0.1.39 (2026-03-07)

### Features

- add status plugin for listing enabled auth plugins

## 0.1.38 (2026-03-07)

### Features

- add password policy, remember me, session binding, and config scaffolding
- add account lockout, webhooks, OIDC, token introspection/revocation, client credentials

## 0.1.37 (2026-03-05)

### Fixes

- accept form-urlencoded POST for OAuth token endpoint (RFC 6749)

## 0.1.36 (2026-03-05)

### Fixes

- accept form-urlencoded POST for OAuth authorize consent

## 0.1.35 (2026-03-05)

### Features

- add consent_ui_url config for browser-based OAuth authorize redirect

## 0.1.34 (2026-03-05)

### Features

- add Device Authorization Grant (RFC 8628) for headless OAuth flows

## 0.1.33 (2026-03-05)

### Fixes

- make redirect_uri optional in authorize endpoint per RFC 6749
- retrigger release with correct Forgejo release history
- align all package versions to 0.1.32 for knope release

## 0.1.32 (2026-03-04)

### Fixes

- ignore ts-rs bindings in biome strict lint
- update doc comments to reflect /oauth/ route namespace
- revert version numbers to let knope manage releases

## 0.1.31 (2026-03-04)

### Fixes

- namespace all oauth2-server routes under /oauth/ to avoid collisions

## 0.1.30 (2026-03-04)

### Features

- implement OAuth2 Authorization Server plugin with JWT support (#4)

## 0.1.29 (2026-02-26)

### Features

- add token refresh support with expires_at tracking

## 0.1.28 (2026-02-26)

### Fixes

- resolve clippy collapsible-if and unnecessary-unwrap

## 0.1.27 (2026-02-26)

### Fixes

- fetch email from emails endpoint when userinfo returns null

## 0.1.26 (2026-02-15)

### Fixes

- sanitize inputs, validate emails, and return consistent JSON errors

## 0.1.25 (2026-02-14)

### Features

- add auto_admin_first_user config option

## 0.1.24 (2026-02-14)

### Fixes

- resolve workspace:* deps to actual versions for npm publish
- re-trigger release after v0.1.23 tag correction

## 0.1.22 (2026-02-14)

### Fixes

- stage biome-reformatted package.json files before commit

## 0.1.21 (2026-02-14)

### Features

- use axum-ts-client format_command for TS client formatting

### Fixes

- apply Biome formatting to generated TS client
- add Biome format step to knope release workflow
- export passkey finish request types for TS client
- add bun to test job for format_command support
- publish packages before git push to prevent cancellation
- add --allow-dirty to cargo publish commands
- install JS deps before knope release for Biome format step

## 0.1.20 (2026-02-14)

### Fixes

- regenerate TS bindings and apply Biome formatting

## 0.1.19 (2026-02-14)

### Fixes

- add yackey-cloud cargo registry and version for axum-ts-client dep

## 0.1.18 (2026-02-14)

### Features

- initial yauth composable auth library
- add change-password endpoint, CI, registry config, and CLAUDE.md
- add PATCH /me profile self-update endpoint
- add showPasskey prop to LoginForm
- support discoverable (usernameless) passkey login
- integrate axum-ts-client for auto-generated TypeScript API client
- add automated semver releases via knope + Forgejo CI

### Fixes

- replace dtolnay/rust-toolchain with rustup install
- use REGISTRY_TOKEN for package publishing
- use token prefix for Cargo registry, fix workspace deps for npm
- use dedicated migration table to avoid conflicts
- use vite with solid plugin for JSX compilation
- use snake_case keys in session endpoint response
- align passkey routes with backend endpoints
- align profile-settings with client 0.1.3 types
- align passkey client with backend response shapes
- extract publicKey from webauthn-rs challenge responses
- improve passkey error handling with user-friendly messages
- revert debug logging, bump to 0.1.12
- use direct event handlers in LoginForm to bypass delegation
- add pointer-events-none to login form divider overlay
- use inline style for pointer-events-none on divider overlay
- add serde(default) for optional email field
- fix knope extraction and clone axum-ts-client in CI
- use in-cluster URL for axum-ts-client clone, use bun publish
- use RELEASE_PAT for authenticated cross-org clone
