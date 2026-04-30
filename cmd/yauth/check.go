package main

import (
	"fmt"

	"github.com/spf13/cobra"
	yauth "github.com/yackey-labs/yauth-go"
	"github.com/yackey-labs/yauth-go/yauthcfg"
)

func newCheckCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:          "check",
		Short:        "Verify schema matches enabled plugins (preflight; non-zero exit on drift)",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := yauthcfg.Load(configPath)
			if err != nil {
				return err
			}
			ctx := cmd.Context()
			if err := yauth.SchemaCheck(ctx, cfg); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "schema OK")
			return nil
		},
	}
	cmd.Flags().StringVarP(&configPath, "config", "c", "yauth.yaml", "path to config file")
	return cmd
}
