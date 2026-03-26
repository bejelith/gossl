//go:build integration

package system

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bejelith/gossl/internal/cli"
	"github.com/bejelith/gossl/internal/store"
)

func gossl(t *testing.T, args ...string) {
	t.Helper()
	cmd := cli.NewRoot("test", "test")
	cmd.SetArgs(args)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("gossl %v: %v", args, err)
	}
}

func getCertSerial(t *testing.T, dbPath, cn string) string {
	t.Helper()
	ctx := context.Background()

	d, err := store.OpenDB(ctx, dbPath)
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	defer d.Close()

	q := store.New(d.SQLDB())
	cert, err := q.GetCertByCN(ctx, cn)
	if err != nil {
		t.Fatalf("GetCertByCN(%s): %v", cn, err)
	}
	return cert.Serial
}

func exportKey(t *testing.T, dbPath, serial, outPath string) {
	t.Helper()
	ctx := context.Background()

	d, err := store.OpenDB(ctx, dbPath)
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	defer d.Close()

	q := store.New(d.SQLDB())
	keyPEM, err := q.LoadKey(ctx, serial)
	if err != nil {
		t.Fatalf("LoadKey(%s): %v", serial, err)
	}

	if err := os.WriteFile(outPath, keyPEM, 0o600); err != nil {
		t.Fatalf("writing key: %v", err)
	}
}

func exportCABundle(t *testing.T, dbPath, outPath string) {
	t.Helper()
	ctx := context.Background()

	d, err := store.OpenDB(ctx, dbPath)
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	defer d.Close()

	q := store.New(d.SQLDB())
	cas, err := q.ListCAs(ctx)
	if err != nil {
		t.Fatalf("ListCAs: %v", err)
	}

	var bundle string
	for _, ca := range cas {
		bundle += ca.CertPem
	}

	if err := os.WriteFile(outPath, []byte(bundle), 0o644); err != nil {
		t.Fatalf("writing CA bundle: %v", err)
	}
}

func buildMTLSClient(t *testing.T, caBundlePath, certPath, keyPath string) *http.Client {
	t.Helper()

	clientCert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatalf("LoadX509KeyPair: %v", err)
	}

	rootCAs := x509.NewCertPool()
	caPEM, err := os.ReadFile(caBundlePath)
	if err != nil {
		t.Fatalf("reading CA bundle: %v", err)
	}
	rootCAs.AppendCertsFromPEM(caPEM)

	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{clientCert},
				RootCAs:      rootCAs,
				ServerName:   "localhost",
			},
		},
		Timeout: 5 * time.Second,
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
}

// setupNginxTLS creates a CA hierarchy, certs, and exports files needed for nginx.
// Returns (dbPath, serverCertPath, serverKeyPath, caBundlePath).
func setupNginxTLS(t *testing.T, caName, intName string) (string, string, string, string) {
	t.Helper()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	gossl(t, "ca", "create", "--cn", caName, "--db", dbPath, "--key-size", "2048")
	gossl(t, "ca", "create", "--cn", intName, "--db", dbPath, "--key-size", "2048")
	gossl(t, "cert", "issue", "--cn", "localhost", "--ca", intName,
		"--san", "localhost,127.0.0.1", "--db", dbPath, "--key-size", "2048")

	serverCertPath := filepath.Join(tmpDir, "server.pem")
	serverKeyPath := filepath.Join(tmpDir, "server-key.pem")
	caBundlePath := filepath.Join(tmpDir, "ca-bundle.pem")

	certSerial := getCertSerial(t, dbPath, "localhost")
	gossl(t, "cert", "export", "--serial", certSerial, "--db", dbPath, "--out", serverCertPath, "--chain")
	exportKey(t, dbPath, certSerial, serverKeyPath)
	exportCABundle(t, dbPath, caBundlePath)

	return dbPath, serverCertPath, serverKeyPath, caBundlePath
}
