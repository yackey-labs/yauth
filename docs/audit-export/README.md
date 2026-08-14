# Audit-log SIEM/syslog export (yauth-go #96)

This is the Go port of yauth Rust PR #106. See `crates/yauth/src/plugins/audit_export/` in `yackey-labs/yauth` for the canonical design.

## What ships

| Surface | Status |
|---|---|
| Plugin scaffolding (`plugins/auditexport/`) | Full |
| Entity types (`domain/audit_export.go`) | Full |
| In-memory destination + outbox store | Full |
| Format adapters: JSON, CEF, RFC 5424 | Full |
| Webhook dispatcher (HMAC-SHA256, Stripe-style replay defense) | Full |
| Syslog UDP / TCP (RFC 6587 octet-counted framing) | Full |
| Syslog TCP+TLS (port 6514) | Stub — `ErrNotImplemented` (mirrors Rust PR scope cut) |
| S3 dispatcher | Wired via test hook; production object-store wiring deferred to follow-up |
| Splunk HEC dispatcher | Stub — `ErrNotImplemented` (mirrors Rust PR scope cut) |
| Datadog logs dispatcher | Stub — `ErrNotImplemented` (mirrors Rust PR scope cut) |
| Drain worker (bounded inflight, backoff, dead-letter after 5 attempts, clean shutdown) | Full |
| Admin routes (deployment-wide + per-org CRUD, outbox listing, replay) | Full |
| OTel metrics (`events_total`, `lag_seconds`, `dead_letter_total`) | Full |
| HMAC signing + `VerifyHMACSignature` receiver helper | Full |
| 10 + 3 pentest cases | Full |
| OpenAPI / generated client wiring | Deferred (matches Rust PR — re-generate after stabilising the route shapes) |

## What lands in the audit log

Everything that reaches `YAuth.Emit` becomes a `yauth_audit_log` row and,
through the plugin's registered `plugin.AuditRecorder`, one outbox entry per
matching destination. Because every credential plugin already funnels its
lifecycle through `Emit`, that covers all of them at once — including
plugins written later.

Rows a **handler** writes itself — administrative actions, which never pass
through `Emit` — reach the same recorder via `plugin.WriteAudit`. They used
not to: they were written straight to the table and delivered nowhere, so a
SIEM streaming yauth received every login and not one ban, impersonation,
SCIM deprovision or client-secret rotation. If your destination filters on
an **allow-list of event types**, widen it — these types are new to the
exported stream even though most of them have been in the table for
releases:

| Event | Written by |
|---|---|
| `admin.ban`, `admin.unban`, `admin.suspend`, `admin.unsuspend`, `admin.impersonation`, `admin.user.deleted`, `admin.session.terminated` | admin plugin (previously table-only) |
| `admin.user_created`, `admin.user_updated`, `admin.schedule_start`, `admin.sessions_revoked` | admin plugin (**new rows** — these four mutations wrote nothing at all; `admin.user_updated` carries `role_from`/`role_to` so a privilege grant is legible without diffing the users table) |
| `apikey.created`, `apikey.revoked`, `apikey.rotated` | **new rows** — personal keys (`plugins/apikey`) and org-scoped service accounts (`plugins/organizations`). Metadata carries `credential_id`, the public `prefix`, `actor_kind` and, for org keys, `organization_id` + `role`. Never the secret or its hash. |
| `oauth2.client.registered`, `oauth2.client.banned_rejected`, `oauth2.client.swept`, and the client-admin rows | oauth2-server plugin (previously table-only) |
| `scim.*` | SCIM plugin (previously table-only) |
| `session_ip_mismatch*`, `session_ua_mismatch*` | middleware session binding (previously table-only) |

The `Emit`-sourced half of the trail is unchanged:

| Event | Recorded |
|---|---|
| `login.succeeded`, `login.failed`, `logout` | Always |
| `user.registered`, `email.verified`, `password.changed`, `password.reset` | Always |
| `user.banned` / `unbanned` / `suspended` / `unsuspended` | Always (in addition to the `admin.*` row the admin plugin writes for the operator action) |
| `login.attempt` | **Only when a gate blocks it** — lockout or an IP block firing. An unblocked attempt is always followed by `login.succeeded`/`login.failed`, so recording it too would double the table to say nothing new. |
| Anything a future plugin emits | Always — the filter is a denylist, not an allowlist |

A blocked or MFA-challenged event carries `decision: "block"` /
`"require_mfa"` (plus `block_status`) in its metadata, so a login a gate
refused is never exported as a plain success. Recorders run whatever the
decision, which an `events.Handler` could not do — a gate's `Block`
short-circuits the handler stage.

`user.unbanned` and `user.unsuspended` are emitted by the admin plugin's
unban/unsuspend routes, so a subscriber that reacted to `user.banned` now
sees the account come back up. SCIM reactivation still emits nothing.

MFA enrolment emits no `AuthEvent` today, so it is not in the trail; it needs
an emission at the point of enrolment first. API-key minting is now covered,
but by a handler-authored `apikey.created` row rather than an `AuthEvent` —
it is in the export stream, not in the event pipeline, so an `events.Handler`
still does not see it.

### Resolver-level failures are deliberately out of scope

A bad API key, a bad bearer token or no credential at all writes **nothing**.
Those are not authentication events — they are the tri-mode resolver
declining to recognise a caller, they occur on every route rather than at a
deliberate credential submission, and they are free for an unauthenticated
stranger to generate. Auditing them would let anyone on the internet drive
unbounded rows into the table, swamp the export pipeline, and bury the
`login.failed` rows that are the actual signal.

This falls out of the design rather than needing a rule: the resolvers emit
no `AuthEvent`, and the audit sink hangs off `Emit`. Because the sink is a
denylist, a resolver that started emitting would be audited by default —
`TestAudit_ResolverLevelCredentialFailuresAreNotAudited` is what catches
that.

A `login.failed` for an address that does not exist **is** recorded, and that
is intentional even though an unauthenticated caller triggers it. A
credential-stuffing sweep is mostly non-existent addresses; an audit log that
recorded failures only for accounts that exist would be blind to the
commonest attack there is, and would hand an attacker a documented way to
probe without leaving a trace. The control for request volume is the request
rate limiter — `RateLimitConfig.Login` defaults to 10/60s — not silently
dropping audit entries. An audit log that discards rows under load is worse
than one with a documented scope.

### What never lands

- No password, token, TOTP code or secret. `AuthEvent` has no field for one,
  and the free-form `Metadata` map is scrubbed: any key containing
  `password`, `token`, `secret`, `code`, `key`, `hash`, `otp`, `recovery`,
  `credential`, `signature` (and similar) has its **value** replaced with
  `[redacted]` while the key stays visible. The scrubber runs on `Emit`
  metadata, which originates in a request; handler-authored rows
  (`plugin.WriteAudit`) are assembled in Go and are not scrubbed, so their
  authors are responsible for never putting a secret in one — which is why
  the API-key rows carry `credential_id` and the public `prefix` and nothing
  else about the credential.
- No control characters. `email`, `method` and `reason` are
  attacker-influenced — `email` is literally whatever was typed into a login
  form — and the RFC 5424 formatter would happily emit an embedded newline
  as a record separator. They are stripped at write time and capped at 320
  bytes.
- No unparseable IP. `ip_address` is dropped unless it parses as an IP, so a
  forged `X-Forwarded-For` cannot put arbitrary text in the column.

## Durability model

Memory-backend semantics are **canonical**: a single mutex guards destination CRUD and outbox enqueue, so the "outbox transactional" invariant holds for in-process operation. Outbox entries are lost on process restart in the memory backend.

SQL persistence is deferred to a follow-up issue — the same precedent as Phase A/B / SAML / SCIM. Production deployments targeting SOC 2 Type II should wait for the SQL backend implementation.

## Routes

All endpoints require an admin cookie session.

```
POST   {prefix}/audit/destinations
GET    {prefix}/audit/destinations
GET    {prefix}/audit/destinations/{id}
PATCH  {prefix}/audit/destinations/{id}
PUT    {prefix}/audit/destinations/{id}      — alias for PATCH
DELETE {prefix}/audit/destinations/{id}
GET    {prefix}/audit/destinations/{id}/outbox
POST   {prefix}/audit/replay                  — { audit_log_ids, destination_ids }

POST   {prefix}/organizations/{org_id}/audit/destinations
GET    {prefix}/organizations/{org_id}/audit/destinations
PATCH  {prefix}/organizations/{org_id}/audit/destinations/{id}
PUT    {prefix}/organizations/{org_id}/audit/destinations/{id}
DELETE {prefix}/organizations/{org_id}/audit/destinations/{id}
```

The plugin sanitises secrets out of every response — `hmac_secret`, `hec_token`, Datadog `api_key`, and any `header.*` static header value are stripped before clients see them. The `hmac_configured` boolean lets the UI render a "secret set" indicator without echoing the secret itself.

## Backoff schedule

Per-attempt next-delay: **1s → 5s → 30s → 5m → 1h** (same as Rust PR #106). After the 5th attempt the outbox row transitions to `dead_letter` and the `yauth_audit_export_dead_letter_total{destination}` counter increments.

## Test guard

Every receiver URL exercised by the pentest harness must be `127.0.0.1`, `localhost`, or a `*.invalid` host. The "no real SIEM endpoints" pentest enforces this contract — see `auditexport_pentest_test.go`.

## Out-of-scope (parity with Rust PR #106)

- Splunk HEC dispatcher — stub returns `ErrNotImplemented`
- Datadog logs dispatcher — stub returns `ErrNotImplemented`
- TCP+TLS syslog — stub returns `ErrNotImplemented` (workaround: `yauth-go → Vector/rsyslog → TLS`)
- Real S3 object-store wiring — needs an object-store client choice
- Test-send button — replay endpoint covers the same workflow
- OpenAPI / generated-client routes — defer until route shapes settle
