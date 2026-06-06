package main

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/yackey-labs/yauth/yauthcfg"
)

func newStatusCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:          "status",
		Short:        "Load + validate config; print enabled plugins",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := yauthcfg.Load(configPath)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "config:    %s\n", configPath)
			fmt.Fprintf(out, "driver:    %s\n", cfg.Database.Driver)
			fmt.Fprintf(out, "telemetry: %t\n", cfg.Telemetry.Enabled)
			plugins := cfg.EnabledPlugins()
			if len(plugins) == 0 {
				fmt.Fprintln(out, "plugins:   (none)")
			} else {
				fmt.Fprintf(out, "plugins:   %s\n", strings.Join(plugins, ", "))
			}

			ep := cfg.Plugins.EmailPassword
			if ep.BootstrapAdmin.Enabled {
				pw := "generated (logged once at first boot)"
				if ep.BootstrapAdmin.Password != "" {
					pw = "operator-provided (not logged)"
				}
				fmt.Fprintf(out, "bootstrap: admin <%s>, password %s\n", ep.BootstrapAdmin.Email, pw)
			}

			for _, warn := range cfg.DeprecationWarnings() {
				fmt.Fprintln(cmd.ErrOrStderr(), "warning: "+warn)
			}
			if ep.BootstrapAdmin.Enabled && cfg.Server.AutoAdminFirstUser {
				fmt.Fprintln(cmd.ErrOrStderr(), "warning: both bootstrap_admin and auto_admin_first_user are set; bootstrap_admin provisions the admin at startup, so auto_admin_first_user (promote-first-registrant) will not fire — disable it.")
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&configPath, "config", "c", "yauth.yaml", "path to config file")
	return cmd
}
