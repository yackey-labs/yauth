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

Implement the interface yourself to route through Resend/SES/Postmark/etc.

## See also

- `yauth docs configuration` — full precedence + the logging section
- `yauth schema config` — the reflected `mailer` schema (descriptions + enum)
- `yauth docs plugins/oidc-provider` — the IdP stack
