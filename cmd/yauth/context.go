package main

import (
	"fmt"
	"reflect"
	"runtime/debug"

	"github.com/spf13/cobra"
	"github.com/yackey-labs/yauth/yauthcfg"
)

// moduleVersion reports the module version stamped into the binary, or
// "(devel)" for un-tagged local builds.
func moduleVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok || info.Main.Version == "" {
		return "(devel)"
	}
	return info.Main.Version
}

// configurablePlugins lists the plugin sections from yauthcfg.PluginsConfig by
// their yaml key, so the catalog can never drift from what this binary parses.
func configurablePlugins() []string {
	t := reflect.TypeOf(yauthcfg.PluginsConfig{})
	names := make([]string, 0, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		name, _ := parseYAMLTag(t.Field(i).Tag.Get("yaml"), t.Field(i).Name)
		names = append(names, name)
	}
	return names
}

func newContextCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "context",
		Short: "Print version-exact agent context (commands, docs, plugins) — start here",
		Long: "Emit an llms.txt-style index of everything this binary can tell an AI " +
			"agent or operator: the commands to run, the embedded docs topics, and the " +
			"configurable plugins. Everything is reflected/embedded from this exact " +
			"version, so it can never drift from the binary.",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			topics, err := docTopics()
			if err != nil {
				return err
			}

			fmt.Fprintf(out, "# yauth — agent context (%s)\n\n", moduleVersion())
			fmt.Fprintln(out, "> yauth is a Go authentication library + operational CLI. This index is")
			fmt.Fprintln(out, "> embedded in the binary, so it matches this exact version. Pull only what")
			fmt.Fprintln(out, "> you need: run a command below, read a docs topic, or fetch the config schema.")
			fmt.Fprintln(out)

			fmt.Fprintln(out, "## Commands")
			fmt.Fprintln(out)
			fmt.Fprintln(out, "- `yauth docs [topic]` — print embedded docs (no arg lists topics; `--full` for all)")
			fmt.Fprintln(out, "- `yauth schema config` — JSON Schema for yauth.yaml, reflected from this binary")
			fmt.Fprintln(out, "- `yauth init` — scaffold a starter yauth.yaml")
			fmt.Fprintln(out, "- `yauth check -c yauth.yaml` — verify schema matches enabled plugins")
			fmt.Fprintln(out, "- `yauth migrate -c yauth.yaml` — run DB migrations (one-shot, before app start)")
			fmt.Fprintln(out, "- `yauth gen-secrets` / `yauth gen-keys` — generate secrets / JWT keypairs")
			fmt.Fprintln(out, "- `yauth status -c yauth.yaml` — load + validate config, print enabled plugins")
			fmt.Fprintln(out, "- `yauth version` — print version info")
			fmt.Fprintln(out, "- `yauth <command> --help` — exact flags for any command")
			fmt.Fprintln(out)

			fmt.Fprintln(out, "## Docs topics")
			fmt.Fprintln(out)
			fmt.Fprintln(out, "Run `yauth docs <topic>`:")
			fmt.Fprintln(out)
			for _, t := range topics {
				fmt.Fprintf(out, "- %s — %s\n", t.Slug, t.Title)
			}
			fmt.Fprintln(out)

			fmt.Fprintln(out, "## Configurable plugins")
			fmt.Fprintln(out)
			fmt.Fprintln(out, "Enable under `plugins:` in yauth.yaml (see `yauth schema config`).")
			fmt.Fprintln(out, "NewFromConfig wires all of these from yaml; secrets/keys come from the")
			fmt.Fprintln(out, "`*_env` fields. For an OIDC IdP / MCP server see `yauth docs plugins/oidc-provider`")
			fmt.Fprintln(out, "and `yauth docs mcp`.")
			fmt.Fprintln(out)
			for _, name := range configurablePlugins() {
				fmt.Fprintf(out, "- %s\n", name)
			}
			fmt.Fprintln(out)

			fmt.Fprintln(out, "## Configuring a server")
			fmt.Fprintln(out)
			fmt.Fprintln(out, "Two paths (mixable): yaml + `yauth.NewFromConfig` (declarative, recommended),")
			fmt.Fprintln(out, "or the builder API `yauth.New(...).WithPlugin(...)`. Mix via")
			fmt.Fprintln(out, "`yauth.NewBuilderFromConfig` then `.WithPlugin(...)`. To share one Postgres")
			fmt.Fprintln(out, "pool, pass `yauth.WithPool(pool)` (or `yauth.WithRepo(repo)` for a custom")
			fmt.Fprintln(out, "storage layer) to NewFromConfig. Precedence rules, env handling, and the")
			fmt.Fprintln(out, "no-duplicate-plugin rule: `yauth docs configuration`.")
			fmt.Fprintln(out)
			fmt.Fprintln(out, "## Email delivery (mailer)")
			fmt.Fprintln(out)
			fmt.Fprintln(out, "email-password, magic-link, and lockout send links that carry single-use")
			fmt.Fprintln(out, "tokens. The DEFAULT `mailer.provider: logging` is dev-only — it writes those")
			fmt.Fprintln(out, "tokens to the log and sends NO email (a one-time WARN fires at startup when")
			fmt.Fprintln(out, "it is active). Set `mailer.provider: smtp` for production. See `yauth docs mailer`.")
			fmt.Fprintln(out)
			fmt.Fprintln(out, "## Telemetry (OpenTelemetry)")
			fmt.Fprintln(out)
			fmt.Fprintln(out, "Enable with `telemetry.enabled: true`. Two modes, set by `manage_provider`:")
			fmt.Fprintln(out, "- `manage_provider: true` (default) — yauth stands up its own OTLP")
			fmt.Fprintln(out, "  exporter + TracerProvider (`otlp_endpoint` / `otlp_protocol`: grpc|http)")
			fmt.Fprintln(out, "  and registers W3C TraceContext + Baggage propagators.")
			fmt.Fprintln(out, "- `manage_provider: false` — your app already configured OpenTelemetry;")
			fmt.Fprintln(out, "  yauth records into the app's provider/propagator and does NOT touch")
			fmt.Fprintln(out, "  them. `otlp_endpoint`/`otlp_protocol` are ignored in this mode.")
			fmt.Fprintln(out, "`http_middleware` (default true) toggles yauth's own HTTP server-span")
			fmt.Fprintln(out, "middleware; set it false when you wrap the whole mux in your own otelhttp")
			fmt.Fprintln(out, "to avoid a double server span. `telemetry.SetUserID(ctx, id)` tags the")
			fmt.Fprintln(out, "current span with `user.id` (semconv); `telemetry.SetUserBaggage(ctx, id)`")
			fmt.Fprintln(out, "puts it in baggage for descendant spans/services. DB query spans come")
			fmt.Fprintln(out, "from `pgxrepo.WithOTelTracing()` (wired automatically by NewFromConfig")
			fmt.Fprintln(out, "when yauth owns the pool).")
			fmt.Fprintln(out)
			fmt.Fprintln(out, "yauth emits these INTERNAL spans (scope \"yauth\"). They are INTERNAL, never")
			fmt.Fprintln(out, "SERVER, so they nest under the caller's root span (your otelhttp server span")
			fmt.Fprintln(out, "when `http_middleware: false`) without a double server span:")
			fmt.Fprintln(out, "- `yauth.resolve` — per-request auth resolution; tags `user.id` +")
			fmt.Fprintln(out, "  `yauth.auth.method` (cookie/bearer/api-key/service-account); session/user lookups nest under it")
			fmt.Fprintln(out, "- `yauth.ratelimit` — fixed-window rate-limit check")
			fmt.Fprintln(out, "- `yauth.user.lookup` — login/register email lookup")
			fmt.Fprintln(out, "- `yauth.password.policy` / `yauth.password.verify` / `yauth.password.breach_check`")
			fmt.Fprintln(out, "- `yauth.session.create` — session issuance")
			fmt.Fprintln(out, "- `yauth.token.verify` — Bearer JWT signature/claims validation")
			fmt.Fprintln(out, "Outbound checks (HIBP breach check, OIDC discovery/JWKS/token, webhook delivery)")
			fmt.Fprintln(out, "use `otelhttp.NewTransport`, so they emit CLIENT spans and propagate W3C")
			fmt.Fprintln(out, "traceparent/baggage. Full guide + app-owns-provider example: `yauth docs telemetry`.")
			fmt.Fprintln(out)
			fmt.Fprintln(out, "## Getting started")
			fmt.Fprintln(out)
			fmt.Fprintln(out, "1. `yauth init` then edit yauth.yaml (validate fields with `yauth schema config`)")
			fmt.Fprintln(out, "2. `yauth check -c yauth.yaml` then `yauth migrate -c yauth.yaml`")
			fmt.Fprintln(out, "3. Set `mailer.provider: smtp` for prod email (`yauth docs mailer`)")
			fmt.Fprintln(out, "4. Frontend: `yauth docs typescript/setup`")

			return nil
		},
	}
}
