package cli

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bejelith/gossl/internal/store"
)

func TestKeyInspect_RSA(t *testing.T) {
	keyPath := writeRSAKeyFile(t, 2048)

	var buf bytes.Buffer
	cmd := NewRoot("test", "test")
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"key", "inspect", keyPath})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("key inspect: %v", err)
	}

	out := buf.String()
	for _, want := range []string{
		"Algorithm:",
		"RSA",
		"Key Size:",
		"2048",
		"Public Key SHA256:",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\nGot:\n%s", want, out)
		}
	}

	// Should NOT contain raw modulus without --raw.
	if strings.Contains(out, "Modulus:") {
		t.Errorf("output should not contain Modulus without --raw\nGot:\n%s", out)
	}
}

func TestKeyInspect_RSA_Raw(t *testing.T) {
	keyPath := writeRSAKeyFile(t, 2048)

	var buf bytes.Buffer
	cmd := NewRoot("test", "test")
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"key", "inspect", keyPath, "--raw"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("key inspect --raw: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "Modulus:") {
		t.Errorf("output missing Modulus with --raw\nGot:\n%s", out)
	}
}

func TestKeyInspect_ECDSA(t *testing.T) {
	keyPath := writeECDSAKeyFile(t, elliptic.P256())

	var buf bytes.Buffer
	cmd := NewRoot("test", "test")
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"key", "inspect", keyPath})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("key inspect: %v", err)
	}

	out := buf.String()
	for _, want := range []string{
		"Algorithm:",
		"ECDSA",
		"Curve:",
		"P-256",
		"Public Key SHA256:",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\nGot:\n%s", want, out)
		}
	}

	if strings.Contains(out, "Public Point:") {
		t.Errorf("output should not contain Public Point without --raw\nGot:\n%s", out)
	}
}

func TestKeyInspect_ECDSA_Raw(t *testing.T) {
	keyPath := writeECDSAKeyFile(t, elliptic.P384())

	var buf bytes.Buffer
	cmd := NewRoot("test", "test")
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"key", "inspect", keyPath, "--raw"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("key inspect --raw: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "Public Point:") {
		t.Errorf("output missing Public Point with --raw\nGot:\n%s", out)
	}
}

func TestKeyInspect_NoArgs(t *testing.T) {
	cmd := NewRoot("test", "test")
	cmd.SetArgs([]string{"key", "inspect"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("key inspect with no args expected error")
	}
}

func TestKeyInspect_BadFile(t *testing.T) {
	badPath := filepath.Join(t.TempDir(), "bad.pem")
	os.WriteFile(badPath, []byte("not a pem"), 0o600)

	cmd := NewRoot("test", "test")
	cmd.SetArgs([]string{"key", "inspect", badPath})
	if err := cmd.Execute(); err == nil {
		t.Fatal("key inspect with bad PEM expected error")
	}
}

func TestKeyInspect_Stdin(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	// Replace stdin.
	oldStdin := os.Stdin
	r, w, _ := os.Pipe()
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = oldStdin })

	go func() {
		w.Write(keyPEM)
		w.Close()
	}()

	var buf bytes.Buffer
	cmd := NewRoot("test", "test")
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"key", "inspect", "-"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("key inspect stdin: %v", err)
	}

	if !strings.Contains(buf.String(), "Public Key SHA256:") {
		t.Errorf("stdin output missing fingerprint\nGot:\n%s", buf.String())
	}
}

func TestCertInspect_ContainsFingerprint(t *testing.T) {
	dbPath, serial := setupTestDB(t)
	outPath := filepath.Join(t.TempDir(), "cert.pem")

	cmd := NewRoot("test", "test")
	cmd.SetArgs([]string{"cert", "export", "--serial", serial, "--db", dbPath, "--out", outPath})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("cert export: %v", err)
	}

	var buf bytes.Buffer
	cmd = NewRoot("test", "test")
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"cert", "inspect", outPath})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("cert inspect: %v", err)
	}

	if !strings.Contains(buf.String(), "Public Key SHA256:") {
		t.Errorf("cert inspect output missing Public Key SHA256\nGot:\n%s", buf.String())
	}
}

func TestKeyAndCertFingerprint_Match(t *testing.T) {
	// Issue a cert via gossl, export the key and cert, verify fingerprints match.
	dbPath := filepath.Join(t.TempDir(), "test.db")
	run := func(args ...string) {
		t.Helper()
		cmd := NewRoot("test", "test")
		cmd.SetArgs(args)
		if err := cmd.Execute(); err != nil {
			t.Fatalf("gossl %v: %v", args, err)
		}
	}

	run("ca", "create", "--cn", "Root CA", "--db", dbPath, "--key-size", "2048")
	run("cert", "issue", "--cn", "match.example.com", "--db", dbPath, "--key-size", "2048")

	// Load the cert and key from DB to get their fingerprints.
	serial := getCertSerialFromDB(t, dbPath, "match.example.com")

	d, err := store.OpenDB(context.Background(), dbPath)
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	defer d.Close()

	q := store.New(d.SQLDB())

	// Get cert fingerprint.
	certRow, err := q.GetCertBySerial(context.Background(), serial)
	if err != nil {
		t.Fatalf("GetCertBySerial: %v", err)
	}
	x509Cert := parseCertPEMFromString(t, certRow.CertPem)
	certFP := publicKeyFingerprint(x509Cert.PublicKey)

	// Get key fingerprint.
	keyPEM, err := q.LoadKey(context.Background(), serial)
	if err != nil {
		t.Fatalf("LoadKey: %v", err)
	}
	privKey, err := parsePrivateKey(keyPEM)
	if err != nil {
		t.Fatalf("parsePrivateKey: %v", err)
	}
	keyFP := publicKeyFingerprint(publicKey(privKey))

	if certFP != keyFP {
		t.Errorf("fingerprints differ: cert=%q key=%q", certFP, keyFP)
	}
}

func TestKeyExport_Basic(t *testing.T) {
	dbPath, _ := setupTestDB(t)
	outPath := filepath.Join(t.TempDir(), "key.pem")

	cmd := NewRoot("test", "test")
	cmd.SetArgs([]string{"key", "export", "--cn", "test.example.com", "--db", dbPath, "--out", outPath})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("key export: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("reading exported key: %v", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("exported file is not valid PEM")
	}
	if block.Type != "RSA PRIVATE KEY" && block.Type != "EC PRIVATE KEY" {
		t.Errorf("unexpected PEM type %q", block.Type)
	}
}

func TestKeyExport_NotFound(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	cmd := NewRoot("test", "test")
	cmd.SetArgs([]string{"ca", "create", "--cn", "Root", "--db", dbPath, "--key-size", "2048"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("ca create: %v", err)
	}

	outPath := filepath.Join(t.TempDir(), "key.pem")
	cmd = NewRoot("test", "test")
	cmd.SetArgs([]string{"key", "export", "--cn", "nonexistent.example.com", "--db", dbPath, "--out", outPath})
	if err := cmd.Execute(); err == nil {
		t.Fatal("key export with bad cn expected error")
	}
}

func TestKeyExport_NoOverwrite(t *testing.T) {
	dbPath, _ := setupTestDB(t)
	outPath := filepath.Join(t.TempDir(), "key.pem")

	os.WriteFile(outPath, []byte("existing"), 0o644)

	cmd := NewRoot("test", "test")
	cmd.SetArgs([]string{"key", "export", "--cn", "test.example.com", "--db", dbPath, "--out", outPath})
	if err := cmd.Execute(); err == nil {
		t.Fatal("key export over existing file expected error")
	}
}

func TestKeyExport_Force(t *testing.T) {
	dbPath, _ := setupTestDB(t)
	outPath := filepath.Join(t.TempDir(), "key.pem")

	os.WriteFile(outPath, []byte("existing"), 0o644)

	cmd := NewRoot("test", "test")
	cmd.SetArgs([]string{"key", "export", "--cn", "test.example.com", "--db", dbPath, "--out", outPath, "--force"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("key export --force: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("reading exported key: %v", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("overwritten file is not valid PEM")
	}
}

func TestKeyExport_Stdout(t *testing.T) {
	dbPath, _ := setupTestDB(t)

	var buf bytes.Buffer
	cmd := NewRoot("test", "test")
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"key", "export", "--cn", "test.example.com", "--db", dbPath})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("key export to stdout: %v", err)
	}

	block, _ := pem.Decode(buf.Bytes())
	if block == nil {
		t.Fatal("stdout output is not valid PEM")
	}
}

// Helpers

func writeRSAKeyFile(t *testing.T, bits int) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	path := filepath.Join(t.TempDir(), "rsa.pem")
	if err := os.WriteFile(path, keyPEM, 0o600); err != nil {
		t.Fatalf("writing key file: %v", err)
	}
	return path
}

func writeECDSAKeyFile(t *testing.T, curve elliptic.Curve) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("generating ECDSA key: %v", err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshalling ECDSA key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	path := filepath.Join(t.TempDir(), "ec.pem")
	if err := os.WriteFile(path, keyPEM, 0o600); err != nil {
		t.Fatalf("writing key file: %v", err)
	}
	return path
}
