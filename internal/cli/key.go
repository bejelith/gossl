package cli

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"io"
	"os"

	"github.com/bejelith/gossl/internal/store"
	"github.com/spf13/cobra"
)

func newKeyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "key",
		Short: "Inspect and export private keys",
	}
	cmd.AddCommand(newKeyInspectCmd())
	cmd.AddCommand(newKeyExportCmd())
	return cmd
}

func newKeyInspectCmd() *cobra.Command {
	var raw bool

	cmd := &cobra.Command{
		Use:   "inspect <file|->",
		Short: "Display private key details",
		Long:  "Inspect a PEM-encoded private key from a file or stdin (-).",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runKeyInspect(cmd, args, raw)
		},
	}

	cmd.Flags().BoolVar(&raw, "raw", false, "Show full modulus or public point in hex")
	return cmd
}

func runKeyInspect(cmd *cobra.Command, args []string, raw bool) error {
	var pemData []byte
	var err error

	if args[0] == "-" {
		pemData, err = io.ReadAll(os.Stdin)
	} else {
		pemData, err = os.ReadFile(args[0])
	}
	if err != nil {
		return fmt.Errorf("reading input: %w", err)
	}

	privKey, err := parsePrivateKey(pemData)
	if err != nil {
		return err
	}

	w := cmd.OutOrStdout()
	printKeyInfo(w, privKey, raw)
	return nil
}

// --- key export ---

func newKeyExportCmd() *cobra.Command {
	var (
		cn    string
		db    string
		out   string
		force bool
	)

	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export a private key from the database",
		Long:  "Export the private key for a certificate by common name.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runKeyExport(cmd.Context(), cmd, cn, db, out, force)
		},
	}

	cmd.Flags().StringVar(&cn, "cn", "", "Certificate common name (required)")
	cmd.Flags().StringVar(&db, "db", "gossl.db", "Path to the SQLite database file")
	cmd.Flags().StringVar(&out, "out", "", "Output file path (defaults to stdout)")
	cmd.Flags().BoolVar(&force, "force", false, "Overwrite existing output file")
	_ = cmd.MarkFlagRequired("cn")

	return cmd
}

func runKeyExport(ctx context.Context, cmd *cobra.Command, cn, dbPath, out string, force bool) error {
	if out != "" && !force {
		if _, err := os.Stat(out); err == nil {
			return fmt.Errorf("file %s already exists (use --force to overwrite)", out)
		}
	}

	d, err := store.OpenDB(ctx, dbPath)
	if err != nil {
		return err
	}
	defer d.Close()

	q := store.New(d.SQLDB())
	cert, err := q.GetCertByCN(ctx, cn)
	if err != nil {
		return fmt.Errorf("certificate %q not found", cn)
	}

	keyPEM, err := q.LoadKey(ctx, cert.Serial)
	if err != nil {
		return fmt.Errorf("key for %q not found", cn)
	}

	if out != "" {
		if err := os.WriteFile(out, keyPEM, 0o600); err != nil {
			return fmt.Errorf("writing key file: %w", err)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Exported key for %q to %s\n", cn, out)
	} else {
		cmd.OutOrStdout().Write(keyPEM)
	}

	return nil
}

func printKeyInfo(w io.Writer, priv any, raw bool) {
	pub := publicKey(priv)

	switch k := priv.(type) {
	case *rsa.PrivateKey:
		fmt.Fprintf(w, "Algorithm:         RSA\n")
		fmt.Fprintf(w, "Key Size:          %d bits\n", k.N.BitLen())
	case *ecdsa.PrivateKey:
		fmt.Fprintf(w, "Algorithm:         ECDSA\n")
		fmt.Fprintf(w, "Curve:             %s\n", k.Curve.Params().Name)
	}

	fmt.Fprintf(w, "Public Key SHA256: %s\n", publicKeyFingerprint(pub))

	if raw {
		switch priv.(type) {
		case *rsa.PrivateKey:
			fmt.Fprintf(w, "Modulus:           %s\n", publicKeyRaw(pub))
		case *ecdsa.PrivateKey:
			fmt.Fprintf(w, "Public Point:      %s\n", publicKeyRaw(pub))
		}
	}
}
