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
			return nil
		},
	}
	cmd.Flags().StringVarP(&configPath, "config", "c", "yauth.yaml", "path to config file")
	return cmd
}
