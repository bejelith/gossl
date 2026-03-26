package cli

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bejelith/gossl/internal/store"
)

func TestServe_DB(t *testing.T) {
	dbPath, certCN, port := setupServeTestDB(t)

	go func() {
		cmd := NewRoot("test", "test")
		cmd.SetArgs([]string{"serve", "--db", dbPath, "--dn", certCN, "--port", fmt.Sprintf("%d", port)})
		cmd.Execute()
	}()

	waitForServer(t, port)

	// Connect with skip verify (self-signed chain)
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 5 * time.Second,
	}

	body := "hello from test"
	resp, err := client.Post(
		fmt.Sprintf("https://localhost:%d/test?foo=bar", port),
		"text/plain",
		strings.NewReader(body),
	)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}

	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading body: %v", err)
	}
	if string(got) != body {
		t.Errorf("body = %q, want %q", got, body)
	}
}

func TestServe_File(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	tmpDir := t.TempDir()

	run := func(args ...string) {
		t.Helper()
		cmd := NewRoot("test", "test")
		cmd.SetArgs(args)
		if err := cmd.Execute(); err != nil {
			t.Fatalf("gossl %v: %v", args, err)
		}
	}

	run("ca", "create", "--cn", "Root", "--db", dbPath, "--key-size", "2048")
	run("cert", "issue", "--cn", "localhost", "--san", "localhost", "--db", dbPath, "--key-size", "2048")

	serial := getCertSerialFromDB(t, dbPath, "localhost")
	certPath := filepath.Join(tmpDir, "server.pem")
	keyPath := filepath.Join(tmpDir, "server-key.pem")

	run("cert", "export", "--serial", serial, "--db", dbPath, "--out", certPath, "--chain")

	d, _ := store.OpenDB(context.Background(), dbPath)
	q := store.New(d.SQLDB())
	keyPEM, _ := q.LoadKey(context.Background(), serial)
	d.Close()
	os.WriteFile(keyPath, keyPEM, 0600)

	port := getFreePort(t)

	go func() {
		cmd := NewRoot("test", "test")
		cmd.SetArgs([]string{"serve", "--cert", certPath, "--pkey", keyPath, "--port", fmt.Sprintf("%d", port)})
		cmd.Execute()
	}()

	waitForServer(t, port)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 5 * time.Second,
	}

	resp, err := client.Get(fmt.Sprintf("https://localhost:%d/", port))
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

func TestServe_MTLS(t *testing.T) {
	dbPath, certCN, port := setupServeTestDB(t)
	tmpDir := t.TempDir()

	run := func(args ...string) {
		t.Helper()
		cmd := NewRoot("test", "test")
		cmd.SetArgs(args)
		if err := cmd.Execute(); err != nil {
			t.Fatalf("gossl %v: %v", args, err)
		}
	}

	// Issue a client cert
	run("cert", "issue", "--cn", "test-client", "--db", dbPath, "--key-size", "2048")
	clientSerial := getCertSerialFromDB(t, dbPath, "test-client")
	clientCertPath := filepath.Join(tmpDir, "client.pem")
	clientKeyPath := filepath.Join(tmpDir, "client-key.pem")
	run("cert", "export", "--serial", clientSerial, "--db", dbPath, "--out", clientCertPath, "--chain")

	d, _ := store.OpenDB(context.Background(), dbPath)
	q := store.New(d.SQLDB())
	clientKeyPEM, _ := q.LoadKey(context.Background(), clientSerial)
	d.Close()
	os.WriteFile(clientKeyPath, clientKeyPEM, 0600)

	go func() {
		cmd := NewRoot("test", "test")
		cmd.SetArgs([]string{"serve", "--db", dbPath, "--dn", certCN, "--port", fmt.Sprintf("%d", port), "--mtls"})
		cmd.Execute()
	}()

	waitForServer(t, port)

	// Connect with client cert
	clientCert, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
	if err != nil {
		t.Fatalf("LoadX509KeyPair: %v", err)
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates:       []tls.Certificate{clientCert},
				InsecureSkipVerify: true,
			},
		},
		Timeout: 5 * time.Second,
	}

	body := "mtls echo"
	resp, err := client.Post(
		fmt.Sprintf("https://localhost:%d/", port),
		"text/plain",
		strings.NewReader(body),
	)
	if err != nil {
		t.Fatalf("POST with mTLS: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}

	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading body: %v", err)
	}
	if string(got) != body {
		t.Errorf("body = %q, want %q", got, body)
	}
}

func TestServe_Metrics(t *testing.T) {
	dbPath, certCN, port := setupServeTestDB(t)

	go func() {
		cmd := NewRoot("test", "test")
		cmd.SetArgs([]string{"serve", "--db", dbPath, "--dn", certCN, "--port", fmt.Sprintf("%d", port)})
		cmd.Execute()
	}()

	waitForServer(t, port)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 5 * time.Second,
	}

	// Make a request so the histogram gets at least one observation.
	resp, err := client.Get(fmt.Sprintf("https://localhost:%d/", port))
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()

	// Scrape the metrics endpoint.
	metricsResp, err := client.Get(fmt.Sprintf("https://localhost:%d/metrics", port))
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer metricsResp.Body.Close()

	if metricsResp.StatusCode != http.StatusOK {
		t.Fatalf("/metrics status = %d, want 200", metricsResp.StatusCode)
	}

	body, err := io.ReadAll(metricsResp.Body)
	if err != nil {
		t.Fatalf("reading /metrics body: %v", err)
	}

	metrics := string(body)
	if !strings.Contains(metrics, "gossl_conn_setup_duration") {
		t.Errorf("/metrics missing gossl_conn_setup_duration histogram\n%s", metrics)
	}
	if !strings.Contains(metrics, "gossl_conn_setup_duration_nanoseconds_count") {
		t.Errorf("/metrics missing _count for histogram\n%s", metrics)
	}
}

func TestServe_MutuallyExclusiveFlags(t *testing.T) {
	cmd := NewRoot("test", "test")
	cmd.SetArgs([]string{"serve", "--db", "test.db", "--dn", "foo", "--cert", "cert.pem", "--pkey", "key.pem"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error with both --db/--dn and --cert/--pkey")
	}
}

func TestServe_MissingPkey(t *testing.T) {
	cmd := NewRoot("test", "test")
	cmd.SetArgs([]string{"serve", "--cert", "cert.pem"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error with --cert but no --pkey")
	}
}

// Helpers

func setupServeTestDB(t *testing.T) (string, string, int) {
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

	run("ca", "create", "--cn", "Root", "--db", dbPath, "--key-size", "2048")
	run("cert", "issue", "--cn", "localhost", "--san", "localhost", "--db", dbPath, "--key-size", "2048")

	return dbPath, "localhost", getFreePort(t)
}

func getFreePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("getFreePort: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port
}

func waitForServer(t *testing.T, port int) {
	t.Helper()
	for i := 0; i < 50; i++ {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("localhost:%d", port), 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("server on port %d did not start", port)
}

