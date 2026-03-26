package cli

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

func newSClientCmd() *cobra.Command {
	var (
		sni       string
		timeout   time.Duration
		caFile    string
		showCerts bool
		clientCrt string
		clientKey string
		alpn      []string
	)

	cmd := &cobra.Command{
		Use:   "sclient <host:port>",
		Short: "Inspect and validate a server's TLS configuration",
		Long: `Connect to a TLS server and display certificate chain, cipher suite,
protocol version, and chain verification status. Similar to openssl s_client.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSClient(args[0], sni, timeout, caFile, showCerts, clientCrt, clientKey, alpn)
		},
	}

	cmd.Flags().StringVar(&sni, "sni", "", "Server name indication override")
	cmd.Flags().DurationVar(&timeout, "timeout", 10*time.Second, "Connection timeout")
	cmd.Flags().StringVar(&caFile, "ca-file", "", "Custom CA bundle for verification")
	cmd.Flags().BoolVar(&showCerts, "show-certs", false, "Print full PEM-encoded certificates")
	cmd.Flags().StringVar(&clientCrt, "cert", "", "Client certificate PEM for mTLS")
	cmd.Flags().StringVar(&clientKey, "key", "", "Client private key PEM for mTLS")
	cmd.Flags().StringSliceVar(&alpn, "alpn", nil, "ALPN protocols (e.g. h2,http/1.1)")

	return cmd
}

func runSClient(addr, sni string, timeout time.Duration, caFile string, showCerts bool, clientCrt, clientKey string, alpn []string) error {
	if !strings.Contains(addr, ":") {
		addr += ":443"
	}

	serverName := sni
	if serverName == "" {
		host, _, _ := strings.Cut(addr, ":")
		serverName = host
	}

	tlsConf := &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
	}

	if len(alpn) > 0 {
		tlsConf.NextProtos = alpn
	}

	// Client cert for mTLS probing
	if clientCrt != "" && clientKey != "" {
		cert, err := tls.LoadX509KeyPair(clientCrt, clientKey)
		if err != nil {
			return fmt.Errorf("loading client certificate: %w", err)
		}
		tlsConf.Certificates = []tls.Certificate{cert}
	}

	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: timeout},
		"tcp", addr, tlsConf,
	)
	if err != nil {
		return fmt.Errorf("connecting to %s: %w", addr, err)
	}
	defer conn.Close()

	state := conn.ConnectionState()

	// Connection info
	fmt.Printf("Connected to %s\n", addr)
	fmt.Printf("  Protocol:       TLS %s\n", tlsVersionString(state.Version))
	fmt.Printf("  Cipher Suite:   %s\n", tls.CipherSuiteName(state.CipherSuite))
	if state.NegotiatedProtocol != "" {
		fmt.Printf("  ALPN:           %s\n", state.NegotiatedProtocol)
	}
	fmt.Println()

	// Certificate chain
	for i, cert := range state.PeerCertificates {
		if i == 0 {
			fmt.Printf("Server Certificate:\n")
		} else {
			fmt.Printf("Chain Certificate [%d]:\n", i)
		}
		printSClientCertInfo(cert)

		if showCerts {
			fmt.Printf("  --- PEM ---\n")
			pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
		}
		fmt.Println()
	}

	// Chain verification
	var roots *x509.CertPool
	if caFile != "" {
		data, err := os.ReadFile(caFile)
		if err != nil {
			return fmt.Errorf("reading CA file: %w", err)
		}
		roots = x509.NewCertPool()
		roots.AppendCertsFromPEM(data)
	}

	if len(state.PeerCertificates) > 0 {
		intermediates := x509.NewCertPool()
		for _, cert := range state.PeerCertificates[1:] {
			intermediates.AddCert(cert)
		}

		opts := x509.VerifyOptions{
			Roots:         roots,
			Intermediates: intermediates,
			DNSName:       serverName,
		}

		_, err := state.PeerCertificates[0].Verify(opts)
		if err != nil {
			fmt.Printf("Chain Verification: FAILED\n")
			fmt.Printf("  Error: %v\n", err)
		} else {
			fmt.Printf("Chain Verification: OK\n")
		}
	}

	return nil
}

func printSClientCertInfo(cert *x509.Certificate) {
	fmt.Printf("  Subject:        %s\n", cert.Subject.String())
	fmt.Printf("  Issuer:         %s\n", cert.Issuer.String())
	fmt.Printf("  Serial:         %X\n", cert.SerialNumber)
	fmt.Printf("  Not Before:     %s\n", cert.NotBefore.Format(time.RFC3339))
	fmt.Printf("  Not After:      %s\n", cert.NotAfter.Format(time.RFC3339))
	fmt.Printf("  Is CA:          %v\n", cert.IsCA)
	fmt.Printf("  Signature Algo: %s\n", cert.SignatureAlgorithm.String())

	// Public key info
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		fmt.Printf("  Public Key:     RSA %d bits\n", pub.N.BitLen())
	case *ecdsa.PublicKey:
		fmt.Printf("  Public Key:     ECDSA %s\n", pub.Curve.Params().Name)
	default:
		fmt.Printf("  Public Key:     %s\n", cert.PublicKeyAlgorithm.String())
	}

	if len(cert.DNSNames) > 0 {
		fmt.Printf("  DNS SANs:       %s\n", strings.Join(cert.DNSNames, ", "))
	}
	if len(cert.IPAddresses) > 0 {
		ips := make([]string, len(cert.IPAddresses))
		for i, ip := range cert.IPAddresses {
			ips[i] = ip.String()
		}
		fmt.Printf("  IP SANs:        %s\n", strings.Join(ips, ", "))
	}

	now := time.Now()
	if now.After(cert.NotAfter) {
		fmt.Printf("  Validity:       EXPIRED (%s ago)\n", now.Sub(cert.NotAfter).Truncate(time.Hour))
	} else if now.Before(cert.NotBefore) {
		fmt.Printf("  Validity:       NOT YET VALID\n")
	} else {
		remaining := cert.NotAfter.Sub(now)
		days := int(remaining.Hours() / 24)
		fmt.Printf("  Validity:       %d days remaining\n", days)
	}
}

func tlsVersionString(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "1.0"
	case tls.VersionTLS11:
		return "1.1"
	case tls.VersionTLS12:
		return "1.2"
	case tls.VersionTLS13:
		return "1.3"
	default:
		return fmt.Sprintf("unknown (0x%04x)", v)
	}
}
