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
