package cli

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/bejelith/gossl/internal/store"
	"github.com/spf13/cobra"
)

func newCACmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ca",
		Short: "Manage certificate authorities",
	}
	cmd.AddCommand(newCACreateCmd())
	cmd.AddCommand(newCAListCmd())
	return cmd
}

func newCACreateCmd() *cobra.Command {
	var (
		cn      string
		db      string
		ca      string
		days    int
		keyAlgo string
		keySize int
		curve   string
	)

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a root CA or intermediate CA",
		Long:  "Create a new CA. Without --ca, creates a self-signed root CA.\nWith --ca, creates an intermediate CA signed by the specified CA.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCACreate(cmd.Context(), cn, db, ca, days, keyAlgo, keySize, curve)
		},
	}

	cmd.Flags().StringVar(&cn, "cn", "", "Common name for the CA (required)")
	cmd.Flags().StringVar(&db, "db", "gossl.db", "Path to the SQLite database file")
	cmd.Flags().StringVar(&ca, "ca", "", "Parent CA common name (omit for root CA)")
	cmd.Flags().IntVar(&days, "days", 3650, "Validity period in days")
	cmd.Flags().StringVar(&keyAlgo, "key-algo", "rsa", "Key algorithm (rsa or ecdsa)")
	cmd.Flags().IntVar(&keySize, "key-size", 4096, "RSA key size in bits")
	cmd.Flags().StringVar(&curve, "curve", "P-256", "ECDSA curve (P-256, P-384, P-521)")
	_ = cmd.MarkFlagRequired("cn")

	return cmd
}

func newCAListCmd() *cobra.Command {
	var db string

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all CAs",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCAList(cmd.Context(), db)
		},
	}

	cmd.Flags().StringVar(&db, "db", "gossl.db", "Path to the SQLite database file")
	return cmd
}

func runCACreate(ctx context.Context, cn, dbPath, parentCN string, days int, keyAlgo string, keySize int, curve string) error {
	privKey, keyPEM, err := generateKey(keyAlgo, keySize, curve)
	if err != nil {
		return err
	}

	serialNumber, err := generateSerial()
	if err != nil {
		return fmt.Errorf("generating serial number: %w", err)
	}

	d, err := store.OpenDB(ctx, dbPath)
	if err != nil {
		return err
	}
	defer d.Close()

	q := store.New(d.SQLDB())
	now := time.Now()
	pubKey := publicKey(privKey)

	var signerCert *x509.Certificate
	var signerKey any
	var parentID sql.NullInt64
	var maxPathLen int
	var label string

	if parentCN == "" {
		// Check if a root CA already exists — if so, default to it as parent
		existingRoot, rootErr := q.GetRootCA(ctx)
		if rootErr == nil {
			// Root exists — this is an intermediate defaulting to root
			parentCN = existingRoot.CommonName
		}
	}

	if parentCN == "" {
		// No root CA exists — self-signed root CA
		signerKey = privKey
		maxPathLen = 2
		label = "root CA"
	} else {
		// Intermediate — find parent
		parent, err := q.GetCAByCN(ctx, parentCN)
		if err != nil {
			return fmt.Errorf("parent CA %q not found", parentCN)
		}
		signerCert, err = parseCertPEMBytes([]byte(parent.CertPem))
		if err != nil {
			return fmt.Errorf("parsing parent certificate: %w", err)
		}
		parentKeyPEM, err := q.LoadKey(ctx, parent.Serial)
		if err != nil {
			return fmt.Errorf("loading parent private key: %w", err)
		}
		signerKey, err = parsePrivateKey(parentKeyPEM)
		if err != nil {
			return fmt.Errorf("parsing parent private key: %w", err)
		}
		parentID = sql.NullInt64{Int64: parent.ID, Valid: true}
		// Reduce maxPathLen from parent
		if signerCert.MaxPathLen > 0 {
			maxPathLen = signerCert.MaxPathLen - 1
		}
		label = fmt.Sprintf("intermediate CA (signed by %q)", parentCN)
	}

	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             now,
		NotAfter:              now.AddDate(0, 0, days),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            maxPathLen,
		MaxPathLenZero:        maxPathLen == 0,
	}

	// For root CA, self-sign
	if signerCert == nil {
		signerCert = template
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, signerCert, pubKey, signerKey)
	if err != nil {
		return fmt.Errorf("creating certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	serial := serialHex(serialNumber)

	_, err = q.CreateCA(ctx, store.CreateCAParams{
		ParentID:   parentID,
		CommonName: cn,
		Serial:     serial,
		KeyAlgo:    keyAlgo,
		CertPem:    string(certPEM),
		NotBefore:  template.NotBefore,
		NotAfter:   template.NotAfter,
		CreatedAt:  now,
	})
	if err != nil {
		return fmt.Errorf("storing CA: %w", err)
	}

	if err := q.StoreKey(ctx, store.StoreKeyParams{ID: serial, KeyPem: keyPEM}); err != nil {
		return fmt.Errorf("storing private key: %w", err)
	}

	fmt.Printf("Created %s %q (serial %s) in %s\n", label, cn, serial, dbPath)
	return nil
}

func runCAList(ctx context.Context, dbPath string) error {
	d, err := store.OpenDB(ctx, dbPath)
	if err != nil {
		return err
	}
	defer d.Close()

	q := store.New(d.SQLDB())
	cas, err := q.ListCAs(ctx)
	if err != nil {
		return fmt.Errorf("listing CAs: %w", err)
	}

	if len(cas) == 0 {
		fmt.Println("No CAs found.")
		return nil
	}

	for _, c := range cas {
		kind := "Root CA"
		if c.ParentID.Valid {
			kind = "Intermediate CA"
		}
		fmt.Printf("%s:\n", kind)
		fmt.Printf("  Common Name: %s\n", c.CommonName)
		fmt.Printf("  Serial:      %s\n", c.Serial)
		fmt.Printf("  Algorithm:   %s\n", c.KeyAlgo)
		fmt.Printf("  Not Before:  %s\n", c.NotBefore.Format(time.RFC3339))
		fmt.Printf("  Not After:   %s\n", c.NotAfter.Format(time.RFC3339))
		fmt.Println()
	}
	return nil
}
