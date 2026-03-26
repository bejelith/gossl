package cli

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/bejelith/gossl/internal/store"
	"github.com/spf13/cobra"
)

func newCertCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cert",
		Short: "Manage and inspect certificates",
	}
	cmd.AddCommand(newCertIssueCmd())
	cmd.AddCommand(newCertSignCmd())
	cmd.AddCommand(newCertListCmd())
	cmd.AddCommand(newCertRevokeCmd())
	cmd.AddCommand(newCertExportCmd())
	cmd.AddCommand(newCertInspectCmd())
	cmd.AddCommand(newCertVerifyCmd())
	return cmd
}

// --- cert issue ---

func newCertIssueCmd() *cobra.Command {
	var (
		cn      string
		db      string
		ca      string
		days    int
		san     string
		keyAlgo string
		keySize int
		curve   string
	)

	cmd := &cobra.Command{
		Use:   "issue",
		Short: "Issue a certificate signed by a CA",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCertIssue(cmd.Context(), cn, db, ca, days, san, keyAlgo, keySize, curve)
		},
	}

	cmd.Flags().StringVar(&cn, "cn", "", "Common name for the certificate (required)")
	cmd.Flags().StringVar(&db, "db", "gossl.db", "Path to the SQLite database file")
	cmd.Flags().StringVar(&ca, "ca", "", "Signing CA common name (defaults to root CA)")
	cmd.Flags().IntVar(&days, "days", 365, "Validity period in days")
	cmd.Flags().StringVar(&san, "san", "", "Subject alternative names (comma-separated)")
	cmd.Flags().StringVar(&keyAlgo, "key-algo", "rsa", "Key algorithm (rsa or ecdsa)")
	cmd.Flags().IntVar(&keySize, "key-size", 4096, "RSA key size in bits")
	cmd.Flags().StringVar(&curve, "curve", "P-256", "ECDSA curve (P-256, P-384, P-521)")
	_ = cmd.MarkFlagRequired("cn")

	return cmd
}

func runCertIssue(ctx context.Context, cn, dbPath, caCN string, days int, san, keyAlgo string, keySize int, curve string) error {
	d, err := store.OpenDB(ctx, dbPath)
	if err != nil {
		return err
	}
	defer d.Close()

	q := store.New(d.SQLDB())

	var caRow store.Ca
	if caCN == "" {
		caRow, err = q.GetRootCA(ctx)
		if err != nil {
			return fmt.Errorf("no root CA found (use --ca to specify)")
		}
	} else {
		caRow, err = q.GetCAByCN(ctx, caCN)
		if err != nil {
			return fmt.Errorf("CA %q not found", caCN)
		}
	}

	caCert, err := parseCertPEMBytes([]byte(caRow.CertPem))
	if err != nil {
		return fmt.Errorf("parsing CA certificate: %w", err)
	}

	caKeyPEM, err := q.LoadKey(ctx, caRow.Serial)
	if err != nil {
		return fmt.Errorf("loading CA private key: %w", err)
	}

	caKey, err := parsePrivateKey(caKeyPEM)
	if err != nil {
		return fmt.Errorf("parsing CA private key: %w", err)
	}

	privKey, keyPEM, err := generateKey(keyAlgo, keySize, curve)
	if err != nil {
		return err
	}

	serialNumber, err := generateSerial()
	if err != nil {
		return fmt.Errorf("generating serial number: %w", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    now,
		NotAfter:     now.AddDate(0, 0, days),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	if san != "" {
		for _, s := range strings.Split(san, ",") {
			s = strings.TrimSpace(s)
			switch {
			case strings.HasPrefix(s, "DNS:"):
				template.DNSNames = append(template.DNSNames, s[len("DNS:"):])
			case strings.HasPrefix(s, "IP:"):
				if ip := net.ParseIP(s[len("IP:"):]); ip != nil {
					template.IPAddresses = append(template.IPAddresses, ip)
				}
			case strings.HasPrefix(s, "EMAIL:"):
				template.EmailAddresses = append(template.EmailAddresses, s[len("EMAIL:"):])
			case strings.HasPrefix(s, "URI:"):
				u, err := url.Parse(s[len("URI:"):])
				if err == nil {
					template.URIs = append(template.URIs, u)
				}
			default:
				// Bare value: auto-detect IP vs DNS
				if ip := net.ParseIP(s); ip != nil {
					template.IPAddresses = append(template.IPAddresses, ip)
				} else {
					template.DNSNames = append(template.DNSNames, s)
				}
			}
		}
	}

	pubKey := publicKey(privKey)
	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, pubKey, caKey)
	if err != nil {
		return fmt.Errorf("creating certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	serial := serialHex(serialNumber)

	_, err = q.CreateCert(ctx, store.CreateCertParams{
		CaID:       caRow.ID,
		CommonName: cn,
		Serial:     serial,
		KeyAlgo:    keyAlgo,
		CertPem:    string(certPEM),
		NotBefore:  template.NotBefore,
		NotAfter:   template.NotAfter,
		CreatedAt:  now,
	})
	if err != nil {
		return fmt.Errorf("storing cert: %w", err)
	}

	if err := q.StoreKey(ctx, store.StoreKeyParams{ID: serial, KeyPem: keyPEM}); err != nil {
		return fmt.Errorf("storing private key: %w", err)
	}

	fmt.Printf("Issued certificate %q (serial %s) signed by %q\n", cn, serial, caRow.CommonName)
	return nil
}

// --- cert sign (from external CSR) ---

func newCertSignCmd() *cobra.Command {
	var (
		db    string
		ca    string
		days  int
		out   string
		force bool
	)

	cmd := &cobra.Command{
		Use:   "sign <csr-file>",
		Short: "Sign an externally generated CSR",
		Long:  "Sign a PEM-encoded CSR file using a CA from the database.\nValidates the CSR signature and enforces minimum key strength requirements.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCertSign(cmd.Context(), args[0], db, ca, days, out, force)
		},
	}

	cmd.Flags().StringVar(&db, "db", "gossl.db", "Path to the SQLite database file")
	cmd.Flags().StringVar(&ca, "ca", "", "Signing CA common name (defaults to root CA)")
	cmd.Flags().IntVar(&days, "days", 365, "Validity period in days")
	cmd.Flags().StringVar(&out, "out", "", "Output certificate PEM file (required)")
	cmd.Flags().BoolVar(&force, "force", false, "Overwrite existing output file")
	_ = cmd.MarkFlagRequired("out")

	return cmd
}

func runCertSign(ctx context.Context, csrFile, dbPath, caCN string, days int, out string, force bool) error {
	if !force {
		if _, err := os.Stat(out); err == nil {
			return fmt.Errorf("file %s already exists (use --force to overwrite)", out)
		}
	}

	// Read and validate CSR
	csrData, err := os.ReadFile(csrFile)
	if err != nil {
		return fmt.Errorf("reading CSR: %w", err)
	}

	csr, err := parseCSRPEMBytes(csrData)
	if err != nil {
		return err
	}

	if err := validateCSRKey(csr); err != nil {
		return fmt.Errorf("CSR key validation failed: %w", err)
	}

	// Open DB and resolve CA
	d, err := store.OpenDB(ctx, dbPath)
	if err != nil {
		return err
	}
	defer d.Close()

	q := store.New(d.SQLDB())

	var caRow store.Ca
	if caCN == "" {
		caRow, err = q.GetRootCA(ctx)
		if err != nil {
			return fmt.Errorf("no root CA found (use --ca to specify)")
		}
	} else {
		caRow, err = q.GetCAByCN(ctx, caCN)
		if err != nil {
			return fmt.Errorf("CA %q not found", caCN)
		}
	}

	caCert, err := parseCertPEMBytes([]byte(caRow.CertPem))
	if err != nil {
		return fmt.Errorf("parsing CA certificate: %w", err)
	}

	caKeyPEM, err := q.LoadKey(ctx, caRow.Serial)
	if err != nil {
		return fmt.Errorf("loading CA private key: %w", err)
	}

	caKey, err := parsePrivateKey(caKeyPEM)
	if err != nil {
		return fmt.Errorf("parsing CA private key: %w", err)
	}

	serialNumber, err := generateSerial()
	if err != nil {
		return fmt.Errorf("generating serial number: %w", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      csr.Subject,
		NotBefore:    now,
		NotAfter:     now.AddDate(0, 0, days),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     csr.DNSNames,
		IPAddresses:  csr.IPAddresses,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, csr.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("creating certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	serial := serialHex(serialNumber)

	// Determine key algo from CSR public key
	keyAlgo := "unknown"
	switch csr.PublicKey.(type) {
	case *rsa.PublicKey:
		keyAlgo = "rsa"
	case *ecdsa.PublicKey:
		keyAlgo = "ecdsa"
	}

	_, err = q.CreateCert(ctx, store.CreateCertParams{
		CaID:       caRow.ID,
		CommonName: csr.Subject.CommonName,
		Serial:     serial,
		KeyAlgo:    keyAlgo,
		CertPem:    string(certPEM),
		NotBefore:  template.NotBefore,
		NotAfter:   template.NotAfter,
		CreatedAt:  now,
	})
	if err != nil {
		return fmt.Errorf("storing cert: %w", err)
	}

	if err := os.WriteFile(out, certPEM, 0o600); err != nil {
		return fmt.Errorf("writing certificate: %w", err)
	}

	fmt.Printf("Signed certificate %q (serial %s) from CSR, signed by %q\n", csr.Subject.CommonName, serial, caRow.CommonName)
	fmt.Printf("Written to %s\n", out)
	return nil
}

// --- cert list ---

func newCertListCmd() *cobra.Command {
	var db string

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all issued certificates",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCertList(cmd.Context(), db)
		},
	}

	cmd.Flags().StringVar(&db, "db", "gossl.db", "Path to the SQLite database file")
	return cmd
}

func runCertList(ctx context.Context, dbPath string) error {
	d, err := store.OpenDB(ctx, dbPath)
	if err != nil {
		return err
	}
	defer d.Close()

	q := store.New(d.SQLDB())
	certs, err := q.ListCerts(ctx)
	if err != nil {
		return fmt.Errorf("listing certs: %w", err)
	}

	if len(certs) == 0 {
		fmt.Println("No certificates found.")
		return nil
	}

	for _, c := range certs {
		status := "active"
		if c.RevokedAt.Valid {
			status = "revoked"
		}
		fmt.Printf("Certificate:\n")
		fmt.Printf("  Common Name: %s\n", c.CommonName)
		fmt.Printf("  Serial:      %s\n", c.Serial)
		fmt.Printf("  Algorithm:   %s\n", c.KeyAlgo)
		fmt.Printf("  Not Before:  %s\n", c.NotBefore.Format(time.RFC3339))
		fmt.Printf("  Not After:   %s\n", c.NotAfter.Format(time.RFC3339))
		fmt.Printf("  Status:      %s\n", status)
		fmt.Println()
	}
	return nil
}

// --- cert revoke ---

func newCertRevokeCmd() *cobra.Command {
	var (
		serial string
		db     string
	)

	cmd := &cobra.Command{
		Use:   "revoke",
		Short: "Revoke a certificate",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCertRevoke(cmd.Context(), serial, db)
		},
	}

	cmd.Flags().StringVar(&serial, "serial", "", "Certificate serial number (required)")
	cmd.Flags().StringVar(&db, "db", "gossl.db", "Path to the SQLite database file")
	_ = cmd.MarkFlagRequired("serial")

	return cmd
}

func runCertRevoke(ctx context.Context, serial, dbPath string) error {
	d, err := store.OpenDB(ctx, dbPath)
	if err != nil {
		return err
	}
	defer d.Close()

	q := store.New(d.SQLDB())
	n, err := q.RevokeCert(ctx, store.RevokeCertParams{
		RevokedAt: sql.NullTime{Time: time.Now(), Valid: true},
		Serial:    serial,
	})
	if err != nil {
		return fmt.Errorf("revoking cert: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("certificate %s not found", serial)
	}

	fmt.Printf("Revoked certificate %s\n", serial)
	return nil
}

// --- cert export ---

func newCertExportCmd() *cobra.Command {
	var (
		serial string
		db     string
		out    string
		chain  bool
		force  bool
	)

	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export a certificate to PEM file",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCertExport(cmd.Context(), serial, db, out, chain, force)
		},
	}

	cmd.Flags().StringVar(&serial, "serial", "", "Certificate serial number (required)")
	cmd.Flags().StringVar(&db, "db", "gossl.db", "Path to the SQLite database file")
	cmd.Flags().StringVar(&out, "out", "", "Output file path (required)")
	cmd.Flags().BoolVar(&chain, "chain", false, "Include full certificate chain")
	cmd.Flags().BoolVar(&force, "force", false, "Overwrite existing file")
	_ = cmd.MarkFlagRequired("serial")
	_ = cmd.MarkFlagRequired("out")

	return cmd
}

func runCertExport(ctx context.Context, serial, dbPath, out string, chain, force bool) error {
	if !force {
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

	cert, err := q.GetCertBySerial(ctx, serial)
	if err != nil {
		return fmt.Errorf("certificate %s not found", serial)
	}

	pemData := cert.CertPem

	if chain {
		// Walk up the CA chain
		caID := cert.CaID
		for {
			caRow, err := q.GetCA(ctx, caID)
			if err != nil {
				break
			}
			pemData += caRow.CertPem
			if !caRow.ParentID.Valid {
				break // reached root
			}
			caID = caRow.ParentID.Int64
		}
	}

	if err := os.WriteFile(out, []byte(pemData), 0o600); err != nil {
		return fmt.Errorf("writing file: %w", err)
	}

	fmt.Printf("Exported certificate %s to %s\n", serial, out)
	return nil
}

// --- cert inspect ---

func newCertInspectCmd() *cobra.Command {
	var (
		db     string
		serial string
	)

	cmd := &cobra.Command{
		Use:   "inspect [file]",
		Short: "Display certificate details",
		Long:  "Inspect a certificate from a PEM file, stdin (-), or the database (--db --serial).",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCertInspect(cmd.Context(), cmd, args, db, serial)
		},
	}

	cmd.Flags().StringVar(&db, "db", "", "Path to the SQLite database file")
	cmd.Flags().StringVar(&serial, "serial", "", "Certificate serial number (with --db)")

	return cmd
}

func runCertInspect(ctx context.Context, cmd *cobra.Command, args []string, dbPath, serial string) error {
	var pemData []byte

	if dbPath != "" && serial != "" {
		d, err := store.OpenDB(ctx, dbPath)
		if err != nil {
			return err
		}
		defer d.Close()

		q := store.New(d.SQLDB())
		cert, err := q.GetCertBySerial(ctx, serial)
		if err != nil {
			return fmt.Errorf("certificate %s not found", serial)
		}
		pemData = []byte(cert.CertPem)
	} else if len(args) > 0 {
		// Unbounded read: CLI tool reads entire PEM into memory for x509 parsing.
		// Let the kernel OOM-kill if input is unreasonably large.
		var err error
		if args[0] == "-" {
			pemData, err = io.ReadAll(os.Stdin)
		} else {
			pemData, err = os.ReadFile(args[0])
		}
		if err != nil {
			return fmt.Errorf("reading input: %w", err)
		}
	} else {
		return fmt.Errorf("provide a file path, '-' for stdin, or --db --serial")
	}

	cert, err := parseCertPEMBytes(pemData)
	if err != nil {
		return err
	}

	printCertInfo(cmd.OutOrStdout(), cert)
	return nil
}

func printCertInfo(w io.Writer, cert *x509.Certificate) {
	fmt.Fprintf(w, "Subject:     %s\n", cert.Subject.String())
	fmt.Fprintf(w, "Issuer:      %s\n", cert.Issuer.String())
	fmt.Fprintf(w, "Serial:      %X\n", cert.SerialNumber)
	fmt.Fprintf(w, "Not Before:  %s\n", cert.NotBefore.Format(time.RFC3339))
	fmt.Fprintf(w, "Not After:   %s\n", cert.NotAfter.Format(time.RFC3339))
	fmt.Fprintf(w, "Is CA:       %v\n", cert.IsCA)

	if len(cert.DNSNames) > 0 {
		fmt.Fprintf(w, "DNS SANs:    %s\n", strings.Join(cert.DNSNames, ", "))
	}
	if len(cert.IPAddresses) > 0 {
		ips := make([]string, len(cert.IPAddresses))
		for i, ip := range cert.IPAddresses {
			ips[i] = ip.String()
		}
		fmt.Fprintf(w, "IP SANs:     %s\n", strings.Join(ips, ", "))
	}

	if cert.PublicKeyAlgorithm != x509.UnknownPublicKeyAlgorithm {
		fmt.Fprintf(w, "Public Key:  %s\n", cert.PublicKeyAlgorithm.String())
	}

	fmt.Fprintf(w, "Public Key SHA256: %s\n", publicKeyFingerprint(cert.PublicKey))
	fmt.Fprintf(w, "Signature:   %s\n", cert.SignatureAlgorithm.String())

	if now := time.Now(); now.After(cert.NotAfter) {
		fmt.Fprintf(w, "Status:      EXPIRED (expired %s ago)\n", now.Sub(cert.NotAfter).Truncate(time.Hour))
	} else {
		fmt.Fprintf(w, "Status:      valid (expires in %s)\n", cert.NotAfter.Sub(now).Truncate(time.Hour))
	}
}

// --- cert verify ---

func newCertVerifyCmd() *cobra.Command {
	var chainFile string

	cmd := &cobra.Command{
		Use:   "verify [file]",
		Short: "Verify a certificate against a CA bundle",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCertVerify(args, chainFile)
		},
	}

	cmd.Flags().StringVar(&chainFile, "chain", "", "CA bundle PEM file (required)")
	_ = cmd.MarkFlagRequired("chain")

	return cmd
}

func runCertVerify(args []string, chainFile string) error {
	if len(args) == 0 {
		return fmt.Errorf("provide a certificate file path or '-' for stdin")
	}

	// Unbounded read: CLI tool reads entire PEM into memory for x509 parsing.
	// Let the kernel OOM-kill if input is unreasonably large.
	var certData []byte
	var err error
	if args[0] == "-" {
		certData, err = io.ReadAll(os.Stdin)
	} else {
		certData, err = os.ReadFile(args[0])
	}
	if err != nil {
		return fmt.Errorf("reading certificate: %w", err)
	}

	chainData, err := os.ReadFile(chainFile)
	if err != nil {
		return fmt.Errorf("reading chain file: %w", err)
	}

	cert, err := parseCertPEMBytes(certData)
	if err != nil {
		return fmt.Errorf("parsing certificate: %w", err)
	}

	roots := x509.NewCertPool()
	intermediates := x509.NewCertPool()

	rest := chainData
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		chainCert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		if chainCert.IsCA && chainCert.Subject.String() == chainCert.Issuer.String() {
			roots.AddCert(chainCert)
		} else {
			intermediates.AddCert(chainCert)
		}
	}

	_, err = cert.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
	})
	if err != nil {
		return fmt.Errorf("verification failed: %w", err)
	}

	fmt.Printf("OK: certificate %q verified successfully\n", cert.Subject.CommonName)
	return nil
}
