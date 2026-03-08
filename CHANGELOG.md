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
