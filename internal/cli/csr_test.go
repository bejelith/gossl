package cli

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestCSRInspect(t *testing.T) {
	csrPath := generateTestCSR(t, "test.example.com", []string{"test.example.com", "www.example.com"})

	cmd := NewRoot("test", "test")
	cmd.SetArgs([]string{"csr", "inspect", csrPath})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("csr inspect: %v", err)
	}
}

func TestCSRInspect_NoArgs(t *testing.T) {
	cmd := NewRoot("test", "test")
	cmd.SetArgs([]string{"csr", "inspect"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("csr inspect with no args expected error")
	}
}

func TestCSRInspect_BadFile(t *testing.T) {
	badPath := filepath.Join(t.TempDir(), "bad.csr")
	os.WriteFile(badPath, []byte("not a PEM"), 0644)

	cmd := NewRoot("test", "test")
	cmd.SetArgs([]string{"csr", "inspect", badPath})
	if err := cmd.Execute(); err == nil {
		t.Fatal("csr inspect bad file expected error")
	}
}

func TestCSRInspect_NonExistentFile(t *testing.T) {
	cmd := NewRoot("test", "test")
	cmd.SetArgs([]string{"csr", "inspect", "/nonexistent/file.csr"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("csr inspect nonexistent file expected error")
	}
}

func generateTestCSR(t *testing.T, cn string, dnsNames []string) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	template := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: cn},
		DNSNames: dnsNames,
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		t.Fatalf("creating CSR: %v", err)
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	csrPath := filepath.Join(t.TempDir(), "test.csr")
	if err := os.WriteFile(csrPath, csrPEM, 0644); err != nil {
		t.Fatalf("writing CSR: %v", err)
	}

	return csrPath
}
