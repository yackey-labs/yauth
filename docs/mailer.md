# Mailer — email delivery (and the dev console-mailer hazard)

Three plugins send email: **email-password** (verification + password-reset
links), **magic-link** (login links), and **lockout** (account-unlock links).
Each link carries a **single-use bearer token** — whoever holds it can verify,
reset, sign in, or unlock the account.

## The default is dev-only and logs tokens

When you do **not** configure a mailer, yauth falls back to a **console
`LoggingMailer`**: it writes the message it *would have emailed* — token and
all — to the logger and **sends no real email**. That's a convenience so local
dev needs no SMTP relay. In production it means **account-takeover tokens land
in your logs** (and anything that ships your logs onward).

To make this impossible to miss, each mail-sending plugin emits a one-time
`WARN` at startup when the console mailer is active:

```
WARN email-password: using the console LoggingMailer — verification & password-reset
links (bearer tokens) are written to logs and NO email is sent; set Config.Mailer
or mailer.provider=smtp for production
```

If you see that line in a deployed service, you have a misconfiguration. Fix it
by configuring a real mailer.

## Pick a provider

| `mailer.provider` | Use for |
|---|---|
| `logging` (default) | **Dev only** — writes tokens to the log, sends nothing |
| `smtp` | Any SMTP relay (including Cloudflare's, see below) |
| `cloudflare` | Cloudflare Email Service over its REST API |

## Configure SMTP (YAML / `NewFromConfig`)

```yaml
mailer:
  provider: smtp                 # default is "logging" (dev-only, see above)
  from: "no-reply@example.com"   # required when provider=smtp
  smtp:
    host: smtp.example.com
    port: 587
    username_env: SMTP_USER      # the env VAR NAME — the secret is read at runtime
    password_env: SMTP_PASS
    tls: true
```

Secrets are referenced by env-var **name** (`*_env`), never inlined, so the
config file stays safe to commit. `NewFromConfig` wires this mailer into all
three plugins automatically. Inspect every field with `yauth schema config`
(the `mailer` block carries inline descriptions and the `provider` enum).

## Configure Cloudflare Email Service (YAML / `NewFromConfig`)

```yaml
mailer:
  provider: cloudflare
  from: "no-reply@example.com"   # domain must be onboarded for Email Sending
  cloudflare:
    account_id: "your-cloudflare-account-id"
    api_token_env: CLOUDFLARE_API_TOKEN   # env VAR NAME, not the token
```

Prerequisites, all on the Cloudflare side:

1. The domain must use **Cloudflare DNS** and be onboarded under
   **Compute → Email Service → Email Sending**. Onboarding adds the SPF,
   DKIM, DMARC and bounce-routing records for you.
2. The API token needs the **Email Sending: Edit** permission, and must
   belong to the account that owns the onboarded domain.
3. `from` must be an address at that onboarded domain.

Startup fails fast if `account_id`, `api_token_env`, or `from` is missing —
**and also if the named env var is unset or empty**, so a missing secret is
a boot error rather than a run of silently vanishing verification emails.

### Bounces are errors, not successes

Cloudflare answers `HTTP 200` with `"success": true` even when it refuses a
recipient outright — the address just lands in `permanent_bounces` instead of
`delivered` or `queued`. Every yauth email carries a single-use token someone
is waiting on, so this mailer treats a bounce (and a recipient that appears
in none of the three lists) as a **hard error** the calling plugin can see.
`queued` counts as success.

### Tracing

Cloudflare sends are traced out of the box — nothing to configure. Each send
opens a `mailer.cloudflare.send` CLIENT span, and the default HTTP client
wraps `otelhttp.NewTransport`, so the outbound call also emits its own CLIENT
span and propagates W3C `traceparent`. Both nest under the caller's request
span when one is present.

The span carries:

| Attribute | Values |
|---|---|
| `mailer.provider` | `cloudflare` |
| `mailer.message.kind` | `verification`, `password_reset`, `account_exists`, `magic_link`, `unlock_token` |
| `mailer.disposition` | `delivered`, `queued`, `bounced`, `unlisted` |
| `http.response.status_code` | Cloudflare's HTTP status |

A bounce sets the span status to **Error**. This is the whole reason the span
exists: the bounce comes back as HTTP 200, so transport-level instrumentation
alone would record a perfectly healthy call for a verification link that went
nowhere. Alert on `mailer.disposition = bounced`.

**Recipient addresses are never recorded as span attributes** — they are PII
and spans get exported off-host. Use `mailer.disposition` plus the message
kind to diagnose; the address stays in your own logs.

If you inject your own `HTTPClient`, it is used verbatim and never mutated —
wrapping its transport is then your responsibility.

### Cloudflare over plain SMTP instead

Cloudflare also exposes an SMTP endpoint, which works with `provider: smtp`
and no Cloudflare-specific config at all — the username is the literal string
`api_token` and the password is the API token:

```yaml
mailer:
  provider: smtp
  from: "no-reply@example.com"
  smtp:
    host: smtp.mx.cloudflare.net
    port: 465
    username_env: CLOUDFLARE_SMTP_USER   # env var containing: api_token
    password_env: CLOUDFLARE_API_TOKEN
    tls: true
```

Prefer `provider: cloudflare` when you want per-recipient delivery status
(the bounce detection above — SMTP gives you none of it) or when egress on
port 465 is unavailable. Prefer `provider: smtp` if you would rather keep one
code path across several mail vendors.

## Custom mailer (`WithMailer` / `NewFromConfig`)

Pass a custom mailer to `NewFromConfig` via `yauth.WithMailer(m)`. When set,
`mailer.provider` in yaml is ignored — your implementation handles all delivery.
The value must implement `yauth.Mailer`, which merges the three plugin interfaces:

```go
type Mailer interface {
    emailpassword.Mailer  // SendVerification, SendPasswordReset, SendAccountExists
    magiclink.Mailer      // SendMagicLink
    lockout.Mailer        // SendUnlockToken
}
```

Example — routing through a transactional email service:

```go
ya, err := yauth.NewFromConfig(ctx, cfg,
    yauth.WithPool(pool),
    yauth.WithMailer(myCustomMailer), // implements all five Send* methods
)
```

`NewFromConfig` wires the mailer into every enabled email-sending plugin
automatically — no per-plugin wiring needed.

## Configure a mailer (builder API)

The builder has no host-level mailer; set `Config.Mailer` on each plugin that
sends. Any type implementing the plugin's small `Mailer` interface works — the
bundled SMTP mailer satisfies all three:

```go
m, _ := smtpmailer.New(smtpmailer.Mailer{
    Host: "smtp.example.com", Port: 587,
    From: "no-reply@example.com",
    Username: os.Getenv("SMTP_USER"), Password: os.Getenv("SMTP_PASS"),
    TLS: true,
})

yauth.New(repo, cfg).
    WithPlugin(emailpassword.New(emailpassword.Config{Mailer: m})).
    WithPlugin(magiclink.New(magiclink.Config{Mailer: m})).
    WithPlugin(lockout.New(lockout.Config{Mailer: m})).
    Build()
```

The Cloudflare mailer drops in the same way — it satisfies all three
interfaces too:

```go
m := cfmailer.New(cfmailer.Mailer{
    AccountID: "your-cloudflare-account-id",
    APIToken:  os.Getenv("CLOUDFLARE_API_TOKEN"),
    From:      "no-reply@example.com",
})
```

Implement the interface yourself to route through Resend/SES/Postmark/etc.

## See also

- `yauth docs configuration` — full precedence + the logging section
- `yauth schema config` — the reflected `mailer` schema (descriptions + enum)
- `yauth docs plugins/oidc-provider` — the IdP stack
