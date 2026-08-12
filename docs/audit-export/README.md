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

MFA enrolment and API-key minting emit no `AuthEvent` today, so they are not
in the trail; they need an emission at the point of enrolment/mint first.

### What never lands

- No password, token, TOTP code or secret. `AuthEvent` has no field for one,
  and the free-form `Metadata` map is scrubbed: any key containing
  `password`, `token`, `secret`, `code`, `key`, `hash`, `otp`, `recovery`,
  `credential`, `signature` (and similar) has its **value** replaced with
  `[redacted]` while the key stays visible.
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
