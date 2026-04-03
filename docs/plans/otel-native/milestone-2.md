# Milestone 2: Migrate span creation + attribute recording to native OTel

**Follow the repo's `CLAUDE.md` exactly. Every rule in it is mandatory.**

### What must work:
1. `auth/password.rs` — `yauth.password_hash` and `yauth.password_verify` spans created via `crate::otel::with_span()`, gated behind telemetry feature
2. `auth/hibp.rs` — `yauth.hibp_check` span created via OTel with `SpanKind::Client`, breach count set as attribute on both child and parent spans via `crate::otel::set_attribute()`. Errors/warnings become span events.
3. `auth/session.rs` — `yauth.session_found` attribute via `crate::otel::set_attribute()`. Session mismatch warnings become span events via `crate::otel::add_event()`
4. `auth/rate_limit.rs` — `yauth.rate_limited` attribute via `crate::otel::set_attribute()`
5. `middleware.rs` — `record_auth_user_on_span()` sets `user.id`, `user.email`, `user.roles`, `yauth.auth_method` via OTel span attributes. Error logging in auth middleware becomes span events.
6. `state.rs` — audit log errors become span events
7. All `tracing::Span`, `tracing::Instrument`, `tracing::info_span!`, `tracing::field::Empty` usage eliminated from these files
8. `cargo test --features full` passes
9. `cargo clippy --features full -- -D warnings` passes

### After building, prove it works:
Start the app with `cargo run --example server --features full`.

- **Password hashing span**: Register a new user. Verify `yauth.password_hash` child span appears in the trace with correct parent.
- **HIBP check span**: Register with password "password". Verify `yauth.hibp_check` span has `SpanKind::Client`, `yauth.hibp.breach_count` attribute on both HIBP span and parent HTTP span.
- **HIBP error as span event**: Disconnect network, attempt registration. Verify the HIBP span has an error event with the failure message (not just a disconnected log line).
- **Session validation**: Login, then `GET /session`. Verify `yauth.session_found=true` attribute on server span.
- **Auth user context**: Hit protected endpoint after login. Verify `user.id`, `user.email`, `user.roles`, `yauth.auth_method=session` on server span.
- **No telemetry build**: `cargo check --features email-password` compiles cleanly.

### Test strategy:
- `cargo test --features full` — all tests pass
- `cargo clippy --features full -- -D warnings` — clean
- `cargo check --features "email-password,passkey,mfa,bearer,api-key,admin"` — non-telemetry build compiles

### Known pitfalls:
1. **HIBP async context propagation**: The current code uses `.instrument(span)` for async context. With OTel, create the child context via `parent_cx.with_span(child_span)` and use `let _guard = child_cx.attach()` at the start of the async block. To set attributes on the parent span, store the parent `Context` before creating the child, then use `parent_cx.span().set_attribute(...)`.
2. **Feature gating pattern**: Use dual `#[cfg]` blocks for functions that set span attributes:
   ```rust
   #[cfg(feature = "telemetry")]
   fn record_auth_user_on_span(user: &AuthUser) { /* OTel */ }
   #[cfg(not(feature = "telemetry"))]
   fn record_auth_user_on_span(_user: &AuthUser) {}
   ```
   Or use the `crate::otel` helpers which handle this internally.
3. **Don't convert ALL tracing calls yet**: This milestone only covers the 5 span-creation files + `state.rs`. The 15+ plugin files with `tracing::error!()` calls are M3. Keep `log` as a bridge for those files in this milestone.
4. **OTel attribute types**: `KeyValue::new()` accepts `Into<Key>` and `Into<Value>`. Use `.to_string()` for `Uuid`. `bool` and `u64` work directly. Don't wrap in `format!()`.
5. **Span event naming**: Use descriptive event names like `"session_ip_mismatch"`, `"hibp_check_failed"`, `"user_lookup_failed"` — not generic `"error"`. Each event name becomes queryable in Honeycomb.
