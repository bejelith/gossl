//go:build integration

package system

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bejelith/gossl/internal/cli"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestMTLS_NginxWithGoSSLCerts(t *testing.T) {
	ctx := context.Background()
	dbPath, serverCertPath, serverKeyPath, caBundlePath := setupNginxTLS(t, "Test Root CA", "Test Intermediate")
	tmpDir := filepath.Dir(serverCertPath)

	// Generate client cert for mTLS
	gossl(t, "cert", "issue", "--cn", "test-client", "--ca", "Test Intermediate",
		"--db", dbPath, "--key-size", "2048")
	clientSerial := getCertSerial(t, dbPath, "test-client")
	clientCertPath := filepath.Join(tmpDir, "client.pem")
	clientKeyPath := filepath.Join(tmpDir, "client-key.pem")
	gossl(t, "cert", "export", "--serial", clientSerial, "--db", dbPath, "--out", clientCertPath, "--chain")
	exportKey(t, dbPath, clientSerial, clientKeyPath)

	nginxConf := filepath.Join(tmpDir, "nginx.conf")
	writeFile(t, nginxConf, `
events {}
http {
    server {
        listen 443 ssl;
        ssl_certificate /etc/nginx/certs/server.pem;
        ssl_certificate_key /etc/nginx/certs/server-key.pem;
        ssl_client_certificate /etc/nginx/certs/ca-bundle.pem;
        ssl_verify_client on;

        location / {
            return 200 "mTLS OK: $ssl_client_s_dn\n";
            add_header Content-Type text/plain;
        }
    }
}
`)

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        "nginx:alpine",
			ExposedPorts: []string{"443/tcp"},
			WaitingFor:   wait.ForListeningPort("443/tcp").WithStartupTimeout(30 * time.Second),
			Files: []testcontainers.ContainerFile{
				{HostFilePath: serverCertPath, ContainerFilePath: "/etc/nginx/certs/server.pem"},
				{HostFilePath: serverKeyPath, ContainerFilePath: "/etc/nginx/certs/server-key.pem"},
				{HostFilePath: caBundlePath, ContainerFilePath: "/etc/nginx/certs/ca-bundle.pem"},
				{HostFilePath: nginxConf, ContainerFilePath: "/etc/nginx/nginx.conf"},
			},
		},
		Started: true,
	})
	if err != nil {
		t.Fatalf("starting nginx container: %v", err)
	}
	defer container.Terminate(ctx)

	mappedPort, _ := container.MappedPort(ctx, "443")
	host, _ := container.Host(ctx)
	addr := fmt.Sprintf("https://%s:%s", host, mappedPort.Port())

	t.Run("valid_client_cert", func(t *testing.T) {
		client := buildMTLSClient(t, caBundlePath, clientCertPath, clientKeyPath)
		resp, err := client.Get(addr)
		if err != nil {
			t.Fatalf("GET %s: %v", addr, err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want 200", resp.StatusCode)
		}
		body, _ := io.ReadAll(resp.Body)
		t.Logf("Response: %s", body)
	})

	t.Run("no_client_cert", func(t *testing.T) {
		rootCAs := x509.NewCertPool()
		caPEM, _ := os.ReadFile(caBundlePath)
		rootCAs.AppendCertsFromPEM(caPEM)

		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{RootCAs: rootCAs},
			},
			Timeout: 5 * time.Second,
		}

		resp, err := client.Get(addr)
		if err != nil {
			t.Logf("Expected TLS error: %v", err)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			t.Fatal("expected rejection without client cert, got 200 OK")
		}
		t.Logf("Rejected with HTTP %d (no client cert)", resp.StatusCode)
	})

	t.Run("cert_verify", func(t *testing.T) {
		cmd := cli.NewRoot("test", "test")
		cmd.SetArgs([]string{"cert", "verify", clientCertPath, "--chain", caBundlePath})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("cert verify: %v", err)
		}
	})
}
