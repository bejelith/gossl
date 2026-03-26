package cli

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/bejelith/gossl/internal/store"
)

func setupSignTestDB(t *testing.T) string {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	cmd := NewRoot("test", "test")
	cmd.SetArgs([]string{"ca", "create", "--cn", "Root CA", "--db", dbPath, "--key-size", "2048"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("ca create: %v", err)
	}
	cmd = NewRoot("test", "test")
	cmd.SetArgs([]string{"ca", "create", "--cn", "Intermediate", "--ca", "Root CA", "--db", dbPath, "--key-size", "2048"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("ca create intermediate: %v", err)
	}
	return dbPath
}

func writeCSR(t *testing.T, key any, cn string, dnsNames []string, ips []net.IP) string {
	t.Helper()
	template := &x509.CertificateRequest{
		Subject:     pkix.Name{CommonName: cn},
		DNSNames:    dnsNames,
		IPAddresses: ips,
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	path := filepath.Join(t.TempDir(), "test.csr")
	os.WriteFile(path, csrPEM, 0644)
	return path
}

func TestCertSign_RSA(t *testing.T) {
	dbPath := setupSignTestDB(t)
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	csrPath := writeCSR(t, key, "rsa.example.com", []string{"rsa.example.com"}, nil)
	outPath := filepath.Join(t.TempDir(), "cert.pem")

	cmd := NewRoot("test", "test")
	cmd.SetArgs([]string{"cert", "sign", csrPath, "--ca", "Intermediate", "--db", dbPath, "--out", outPath})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("cert sign: %v", err)
	}

	cert := parseCertPEMFromString(t, string(must(os.ReadFile(outPath))))
	if cert.Subject.CommonName != "rsa.example.com" {
		t.Errorf("CN = %q, want %q", cert.Subject.CommonName, "rsa.example.com")
	}
	if cert.Issuer.CommonName != "Intermediate" {
		t.Errorf("Issuer = %q, want %q", cert.Issuer.CommonName, "Intermediate")
	}
	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != "rsa.example.com" {
		t.Errorf("DNSNames = %v", cert.DNSNames)
	}
}

func TestCertSign_ECDSA(t *testing.T) {
	dbPath := setupSignTestDB(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrPath := writeCSR(t, key, "ec.example.com", []string{"ec.example.com"}, []net.IP{net.ParseIP("10.0.0.1")})
	outPath := filepath.Join(t.TempDir(), "cert.pem")

	cmd := NewRoot("test", "test")
	cmd.SetArgs([]string{"cert", "sign", csrPath, "--db", dbPath, "--out", outPath})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("cert sign: %v", err)
	}

	cert := parseCertPEMFromString(t, string(must(os.ReadFile(outPath))))
	if cert.PublicKeyAlgorithm != x509.ECDSA {
		t.Errorf("PublicKeyAlgorithm = %v, want ECDSA", cert.PublicKeyAlgorithm)
	}
	if len(cert.IPAddresses) != 1 || cert.IPAddresses[0].String() != "10.0.0.1" {
		t.Errorf("IPAddresses = %v", cert.IPAddresses)
	}
}

func TestCertSign_WeakRSAKey(t *testing.T) {
	dbPath := setupSignTestDB(t)
	key, _ := rsa.GenerateKey(rand.Reader, 1024)
	csrPath := writeCSR(t, key, "weak.example.com", nil, nil)
	outPath := filepath.Join(t.TempDir(), "cert.pem")

	cmd := NewRoot("test", "test")
	cmd.SetArgs([]string{"cert", "sign", csrPath, "--db", dbPath, "--out", outPath})
	if err := cmd.Execute(); err == nil {
		t.Fatal("cert sign with 1024-bit RSA expected error")
	}
}

func TestCertSign_StoredInDB(t *testing.T) {
	dbPath := setupSignTestDB(t)
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	csrPath := writeCSR(t, key, "stored.example.com", nil, nil)
	outPath := filepath.Join(t.TempDir(), "cert.pem")

	cmd := NewRoot("test", "test")
	cmd.SetArgs([]string{"cert", "sign", csrPath, "--db", dbPath, "--out", outPath})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("cert sign: %v", err)
	}

	d, _ := store.OpenDB(context.Background(), dbPath)
	defer d.Close()
	q := store.New(d.SQLDB())
	cert, err := q.GetCertByCN(context.Background(), "stored.example.com")
	if err != nil {
		t.Fatalf("cert not stored in DB: %v", err)
	}
	if cert.KeyAlgo != "rsa" {
		t.Errorf("KeyAlgo = %q, want %q", cert.KeyAlgo, "rsa")
	}
}

func TestCertSign_NoOverwrite(t *testing.T) {
	dbPath := setupSignTestDB(t)
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	csrPath := writeCSR(t, key, "test.example.com", nil, nil)
	outPath := filepath.Join(t.TempDir(), "cert.pem")
	os.WriteFile(outPath, []byte("existing"), 0644)

	cmd := NewRoot("test", "test")
	cmd.SetArgs([]string{"cert", "sign", csrPath, "--db", dbPath, "--out", outPath})
	if err := cmd.Execute(); err == nil {
		t.Fatal("cert sign over existing file expected error")
	}
}

func TestCertSign_Force(t *testing.T) {
	dbPath := setupSignTestDB(t)
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	csrPath := writeCSR(t, key, "test.example.com", nil, nil)
	outPath := filepath.Join(t.TempDir(), "cert.pem")
	os.WriteFile(outPath, []byte("existing"), 0644)

	cmd := NewRoot("test", "test")
	cmd.SetArgs([]string{"cert", "sign", csrPath, "--db", dbPath, "--out", outPath, "--force"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("cert sign --force: %v", err)
	}
}

func TestCertSign_BadCSR(t *testing.T) {
	dbPath := setupSignTestDB(t)
	badCSR := filepath.Join(t.TempDir(), "bad.csr")
	os.WriteFile(badCSR, []byte("not a PEM"), 0644)
	outPath := filepath.Join(t.TempDir(), "cert.pem")

	cmd := NewRoot("test", "test")
	cmd.SetArgs([]string{"cert", "sign", badCSR, "--db", dbPath, "--out", outPath})
	if err := cmd.Execute(); err == nil {
		t.Fatal("cert sign bad CSR expected error")
	}
}

func TestCertSign_DefaultsToRootCA(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	cmd := NewRoot("test", "test")
	cmd.SetArgs([]string{"ca", "create", "--cn", "Only Root", "--db", dbPath, "--key-size", "2048"})
	cmd.Execute()

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	csrPath := writeCSR(t, key, "direct.example.com", nil, nil)
	outPath := filepath.Join(t.TempDir(), "cert.pem")

	cmd = NewRoot("test", "test")
	cmd.SetArgs([]string{"cert", "sign", csrPath, "--db", dbPath, "--out", outPath})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("cert sign: %v", err)
	}

	cert := parseCertPEMFromString(t, string(must(os.ReadFile(outPath))))
	if cert.Issuer.CommonName != "Only Root" {
		t.Errorf("Issuer = %q, want %q", cert.Issuer.CommonName, "Only Root")
	}
}

func TestValidateCSRKey_RSA_OK(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	csr := createCSR(t, key, "test")
	if err := validateCSRKey(csr); err != nil {
		t.Errorf("validateCSRKey(2048) = %v, want nil", err)
	}
}

func TestValidateCSRKey_RSA_TooSmall(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 1024)
	csr := createCSR(t, key, "test")
	if err := validateCSRKey(csr); err == nil {
		t.Error("validateCSRKey(1024) = nil, want error")
	}
}

func TestValidateCSRKey_ECDSA_OK(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr := createCSR(t, key, "test")
	if err := validateCSRKey(csr); err != nil {
		t.Errorf("validateCSRKey(P-256) = %v, want nil", err)
	}
}

func createCSR(t *testing.T, key any, cn string) *x509.CertificateRequest {
	t.Helper()
	template := &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}
	der, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("ParseCertificateRequest: %v", err)
	}
	return csr
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
