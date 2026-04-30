package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/yackey-labs/yauth-go/yauthcfg"
)

func newInitCmd() *cobra.Command {
	var (
		out   string
		force bool
	)
	cmd := &cobra.Command{
		Use:          "init",
		Short:        "Write a default yauth.yaml to disk",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if !force {
				if _, err := os.Stat(out); err == nil {
					return fmt.Errorf("%s already exists; pass --force to overwrite", out)
				}
			}
			body, err := yauthcfg.Encode(yauthcfg.Default())
			if err != nil {
				return fmt.Errorf("encode default config: %w", err)
			}
			if err := os.WriteFile(out, body, 0o600); err != nil {
				return fmt.Errorf("write %s: %w", out, err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "wrote %s\n", out)
			return nil
		},
	}
	cmd.Flags().StringVarP(&out, "out", "o", "yauth.yaml", "path to write")
	cmd.Flags().BoolVar(&force, "force", false, "overwrite if file exists")
	return cmd
}
