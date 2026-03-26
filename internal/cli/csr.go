package cli

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

func newCSRCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "csr",
		Short: "Inspect certificate signing requests",
	}
	cmd.AddCommand(newCSRInspectCmd())
	return cmd
}

func newCSRInspectCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "inspect [file]",
		Short: "Display CSR details",
		Long:  "Inspect a certificate signing request from a PEM file or stdin (-).",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCSRInspect(args)
		},
	}
	return cmd
}

func runCSRInspect(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("provide a CSR file path or '-' for stdin")
	}

	// Unbounded read: CLI tool reads entire PEM into memory for x509 parsing.
	// Let the kernel OOM-kill if input is unreasonably large.
	var data []byte
	var err error
	if args[0] == "-" {
		data, err = io.ReadAll(os.Stdin)
	} else {
		data, err = os.ReadFile(args[0])
	}
	if err != nil {
		return fmt.Errorf("reading input: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return fmt.Errorf("failed to decode PEM")
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return fmt.Errorf("parsing CSR: %w", err)
	}

	if err := csr.CheckSignature(); err != nil {
		fmt.Printf("WARNING: CSR signature verification failed: %v\n", err)
	}

	fmt.Printf("Subject:     %s\n", csr.Subject.String())
	if len(csr.DNSNames) > 0 {
		fmt.Printf("DNS SANs:    %s\n", strings.Join(csr.DNSNames, ", "))
	}
	if len(csr.IPAddresses) > 0 {
		ips := make([]string, len(csr.IPAddresses))
		for i, ip := range csr.IPAddresses {
			ips[i] = ip.String()
		}
		fmt.Printf("IP SANs:     %s\n", strings.Join(ips, ", "))
	}
	fmt.Printf("Public Key:  %s\n", csr.PublicKeyAlgorithm.String())
	fmt.Printf("Signature:   %s\n", csr.SignatureAlgorithm.String())

	return nil
}
