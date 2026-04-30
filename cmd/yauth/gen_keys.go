package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

func newGenKeysCmd() *cobra.Command {
	var (
		keyType string
		outDir  string
	)
	cmd := &cobra.Command{
		Use:          "gen-keys",
		Short:        "Generate an RSA-2048 or ECDSA-P256 keypair (private.pem / public.pem)",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			privPEM, pubPEM, err := generateKeyPair(keyType)
			if err != nil {
				return err
			}
			if err := os.MkdirAll(outDir, 0o700); err != nil {
				return fmt.Errorf("mkdir %s: %w", outDir, err)
			}
			privPath := filepath.Join(outDir, "private.pem")
			pubPath := filepath.Join(outDir, "public.pem")
			if err := os.WriteFile(privPath, privPEM, 0o600); err != nil {
				return fmt.Errorf("write private key: %w", err)
			}
			if err := os.WriteFile(pubPath, pubPEM, 0o644); err != nil {
				return fmt.Errorf("write public key: %w", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "wrote %s and %s (%s)\n", privPath, pubPath, keyType)
			return nil
		},
	}
	cmd.Flags().StringVar(&keyType, "type", "rs256", "key type (rs256 | es256)")
	cmd.Flags().StringVar(&outDir, "out", "./keys", "output directory")
	return cmd
}

func generateKeyPair(keyType string) (priv, pub []byte, err error) {
	switch keyType {
	case "rs256":
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, nil, err
		}
		privDER, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			return nil, nil, err
		}
		pubDER, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
		if err != nil {
			return nil, nil, err
		}
		return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}),
			pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}),
			nil
	case "es256":
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		privDER, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			return nil, nil, err
		}
		pubDER, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
		if err != nil {
			return nil, nil, err
		}
		return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}),
			pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}),
			nil
	default:
		return nil, nil, fmt.Errorf("unsupported --type %q (rs256 | es256)", keyType)
	}
}
