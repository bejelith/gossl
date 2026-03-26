package cli

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/bejelith/gossl/internal/store"
)

// setupTestDB creates a DB with root CA, intermediate, and a leaf cert. Returns db path and leaf serial.
func setupTestDB(t *testing.T) (string, string) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")

	run := func(args ...string) {
		t.Helper()
		cmd := NewRoot("test", "test")
		cmd.SetArgs(args)
		if err := cmd.Execute(); err != nil {
			t.Fatalf("gossl %v: %v", args, err)
		}
	}

	run("ca", "create", "--cn", "Test Root CA", "--db", dbPath, "--key-size", "2048")
	run("ca", "create", "--cn", "Test Intermediate", "--ca", "Test Root CA", "--db", dbPath, "--key-size", "2048")
	run("cert", "issue", "--cn", "test.example.com", "--ca", "Test Intermediate",
		"--san", "test.example.com,10.0.0.1", "--db", dbPath, "--key-size", "2048")

	serial := getCertSerialFromDB(t, dbPath, "test.example.com")
	return dbPath, serial
}

func getCertSerialFromDB(t *testing.T, dbPath, cn string) string {
	t.Helper()
	d, err := store.OpenDB(context.Background(), dbPath)
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	defer d.Close()
	q := store.New(d.SQLDB())
	cert, err := q.GetCertByCN(context.Background(), cn)
	if err != nil {
		t.Fatalf("GetCertByCN(%s): %v", cn, err)
	}
	return cert.Serial
}

func TestCertIssue_Basic(t *testing.T) {
	dbPath, serial := setupTestDB(t)

	d, err := store.OpenDB(context.Background(), dbPath)
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	defer d.Close()

	q := store.New(d.SQLDB())
	cert, err := q.GetCertBySerial(context.Background(), serial)
	if err != nil {
		t.Fatalf("GetCertBySerial: %v", err)
	}

	if cert.CommonName != "test.example.com" {
		t.Errorf("CommonName = %q, want %q", cert.CommonName, "test.example.com")
	}

	// Verify cert is signed by intermediate
	x509Cert := parseCertPEMFromString(t, cert.CertPem)
	if x509Cert.Issuer.CommonName != "Test Intermediate" {
		t.Errorf("Issuer = %q, want %q", x509Cert.Issuer.CommonName, "Test Intermediate")
	}
	if x509Cert.IsCA {
		t.Error("leaf cert should not be CA")
	}
}

func TestCertIssue_SANs(t *testing.T) {
	dbPath, serial := setupTestDB(t)

	d, err := store.OpenDB(context.Background(), dbPath)
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	defer d.Close()

	q := store.New(d.SQLDB())
	cert, err := q.GetCertBySerial(context.Background(), serial)
	if err != nil {
		t.Fatalf("GetCertBySerial: %v", err)
	}

	x509Cert := parseCertPEMFromString(t, cert.CertPem)
	if len(x509Cert.DNSNames) != 1 || x509Cert.DNSNames[0] != "test.example.com" {
		t.Errorf("DNSNames = %v, want [test.example.com]", x509Cert.DNSNames)
	}
	if len(x509Cert.IPAddresses) != 1 || x509Cert.IPAddresses[0].String() != "10.0.0.1" {
		t.Errorf("IPAddresses = %v, want [10.0.0.1]", x509Cert.IPAddresses)
	}
}

func TestCertIssue_DefaultsToRootCA(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	cmd := NewRoot("test", "test")
	cmd.SetArgs([]string{"ca", "create", "--cn", "Root", "--db", dbPath, "--key-size", "2048"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("ca create: %v", err)
	}

	cmd = NewRoot("test", "test")
	cmd.SetArgs([]string{"cert", "issue", "--cn", "direct.example.com", "--db", dbPath, "--key-size", "2048"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("cert issue: %v", err)
	}

	d, err := store.OpenDB(context.Background(), dbPath)
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	defer d.Close()
	q := store.New(d.SQLDB())
	cert, err := q.GetCertByCN(context.Background(), "direct.example.com")
	if err != nil {
		t.Fatalf("GetCertByCN: %v", err)
	}

	x509Cert := parseCertPEMFromString(t, cert.CertPem)
	if x509Cert.Issuer.CommonName != "Root" {
		t.Errorf("Issuer = %q, want %q", x509Cert.Issuer.CommonName, "Root")
	}
}

func TestCertIssue_BadCA(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	cmd := NewRoot("test", "test")
	cmd.SetArgs([]string{"ca", "create", "--cn", "Root", "--db", dbPath, "--key-size", "2048"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("ca create: %v", err)
	}

	cmd = NewRoot("test", "test")
	cmd.SetArgs([]string{"cert", "issue", "--cn", "bad.example.com", "--ca", "NonExistent", "--db", dbPath, "--key-size", "2048"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("cert issue with bad --ca expected error")
	}
}

func TestCertList(t *testing.T) {
	dbPath, _ := setupTestDB(t)

	cmd := NewRoot("test", "test")
	cmd.SetArgs([]string{"cert", "list", "--db", dbPath})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("cert list: %v", err)
	}
}

func TestCertRevoke(t *testing.T) {
	dbPath, serial := setupTestDB(t)

	cmd := NewRoot("test", "test")
	cmd.SetArgs([]string{"cert", "revoke", "--serial", serial, "--db", dbPath})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("cert revoke: %v", err)
	}

	// Verify revoked
	d, err := store.OpenDB(context.Background(), dbPath)
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	defer d.Close()
	q := store.New(d.SQLDB())
	cert, err := q.GetCertBySerial(context.Background(), serial)
	if err != nil {
		t.Fatalf("GetCertBySerial: %v", err)
	}
	if !cert.RevokedAt.Valid {
		t.Error("cert should be revoked")
	}
}

func TestCertRevoke_NotFound(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	cmd := NewRoot("test", "test")
	cmd.SetArgs([]string{"ca", "create", "--cn", "Root", "--db", dbPath, "--key-size", "2048"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("ca create: %v", err)
	}

	cmd = NewRoot("test", "test")
	cmd.SetArgs([]string{"cert", "revoke", "--serial", "NONEXISTENT", "--db", dbPath})
	if err := cmd.Execute(); err == nil {
		t.Fatal("cert revoke nonexistent expected error")
	}
}

func TestCertExport(t *testing.T) {
	dbPath, serial := setupTestDB(t)
	outPath := filepath.Join(t.TempDir(), "cert.pem")

	cmd := NewRoot("test", "test")
	cmd.SetArgs([]string{"cert", "export", "--serial", serial, "--db", dbPath, "--out", outPath})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("cert export: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("reading exported cert: %v", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("exported file is not valid PEM")
	}
}

func TestCertExport_Chain(t *testing.T) {
	dbPath, serial := setupTestDB(t)
	outPath := filepath.Join(t.TempDir(), "chain.pem")

	cmd := NewRoot("test", "test")
	cmd.SetArgs([]string{"cert", "export", "--serial", serial, "--db", dbPath, "--out", outPath, "--chain"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("cert export --chain: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("reading chain: %v", err)
	}

	// Should contain 3 certs: leaf + intermediate + root
	count := 0
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		count++
	}
	if count != 3 {
		t.Errorf("chain contains %d certs, want 3", count)
	}
}

func TestCertExport_NoOverwrite(t *testing.T) {
	dbPath, serial := setupTestDB(t)
	outPath := filepath.Join(t.TempDir(), "cert.pem")

	// Create the file first
	os.WriteFile(outPath, []byte("existing"), 0644)

	cmd := NewRoot("test", "test")
	cmd.SetArgs([]string{"cert", "export", "--serial", serial, "--db", dbPath, "--out", outPath})
	if err := cmd.Execute(); err == nil {
		t.Fatal("cert export over existing file expected error")
	}
}

func TestCertExport_Force(t *testing.T) {
	dbPath, serial := setupTestDB(t)
	outPath := filepath.Join(t.TempDir(), "cert.pem")

	os.WriteFile(outPath, []byte("existing"), 0644)

	cmd := NewRoot("test", "test")
	cmd.SetArgs([]string{"cert", "export", "--serial", serial, "--db", dbPath, "--out", outPath, "--force"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("cert export --force: %v", err)
	}
}

func TestCertInspect_File(t *testing.T) {
	dbPath, serial := setupTestDB(t)
	outPath := filepath.Join(t.TempDir(), "cert.pem")

	cmd := NewRoot("test", "test")
	cmd.SetArgs([]string{"cert", "export", "--serial", serial, "--db", dbPath, "--out", outPath})
	cmd.Execute()

	cmd = NewRoot("test", "test")
	cmd.SetArgs([]string{"cert", "inspect", outPath})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("cert inspect: %v", err)
	}
}

func TestCertInspect_DB(t *testing.T) {
	dbPath, serial := setupTestDB(t)

	cmd := NewRoot("test", "test")
	cmd.SetArgs([]string{"cert", "inspect", "--db", dbPath, "--serial", serial})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("cert inspect --db: %v", err)
	}
}

func TestCertInspect_NoArgs(t *testing.T) {
	cmd := NewRoot("test", "test")
	cmd.SetArgs([]string{"cert", "inspect"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("cert inspect with no args expected error")
	}
}

func TestCertVerify_ValidChain(t *testing.T) {
	dbPath, serial := setupTestDB(t)
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "leaf.pem")
	chainPath := filepath.Join(tmpDir, "chain.pem")

	cmd := NewRoot("test", "test")
	cmd.SetArgs([]string{"cert", "export", "--serial", serial, "--db", dbPath, "--out", certPath})
	cmd.Execute()

	cmd = NewRoot("test", "test")
	cmd.SetArgs([]string{"cert", "export", "--serial", serial, "--db", dbPath, "--out", chainPath, "--chain", "--force"})
	cmd.Execute()

	cmd = NewRoot("test", "test")
	cmd.SetArgs([]string{"cert", "verify", certPath, "--chain", chainPath})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("cert verify: %v", err)
	}
}

func TestCertVerify_BadChain(t *testing.T) {
	dbPath, serial := setupTestDB(t)
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "leaf.pem")

	cmd := NewRoot("test", "test")
	cmd.SetArgs([]string{"cert", "export", "--serial", serial, "--db", dbPath, "--out", certPath})
	cmd.Execute()

	// Create a different CA's cert as chain — verification should fail
	otherDBPath := filepath.Join(tmpDir, "other.db")
	cmd = NewRoot("test", "test")
	cmd.SetArgs([]string{"ca", "create", "--cn", "Other Root CA", "--db", otherDBPath, "--key-size", "2048"})
	cmd.Execute()

	otherChainPath := filepath.Join(tmpDir, "other-chain.pem")
	d, _ := store.OpenDB(context.Background(), otherDBPath)
	q := store.New(d.SQLDB())
	otherCA, _ := q.GetRootCA(context.Background())
	os.WriteFile(otherChainPath, []byte(otherCA.CertPem), 0644)
	d.Close()

	cmd = NewRoot("test", "test")
	cmd.SetArgs([]string{"cert", "verify", certPath, "--chain", otherChainPath})
	if err := cmd.Execute(); err == nil {
		t.Fatal("cert verify with wrong chain expected error")
	}
}

func TestCertIssue_ECDSA(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	run := func(args ...string) {
		t.Helper()
		cmd := NewRoot("test", "test")
		cmd.SetArgs(args)
		if err := cmd.Execute(); err != nil {
			t.Fatalf("gossl %v: %v", args, err)
		}
	}

	run("ca", "create", "--cn", "Root", "--db", dbPath, "--key-size", "2048")
	run("cert", "issue", "--cn", "ecdsa.example.com", "--db", dbPath, "--key-algo", "ecdsa", "--curve", "P-256")

	d, _ := store.OpenDB(context.Background(), dbPath)
	defer d.Close()
	q := store.New(d.SQLDB())
	cert, _ := q.GetCertByCN(context.Background(), "ecdsa.example.com")

	x509Cert := parseCertPEMFromString(t, cert.CertPem)
	if x509Cert.PublicKeyAlgorithm != x509.ECDSA {
		t.Errorf("PublicKeyAlgorithm = %v, want ECDSA", x509Cert.PublicKeyAlgorithm)
	}
}
