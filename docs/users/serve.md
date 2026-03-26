# HTTPS Echo Server (serve)

`gossl serve` starts a local HTTPS server that echoes the request body back to the caller. When verbose mode is enabled, request headers are copied to the response headers. It is useful for testing TLS configurations, client certificate setups, and verifying connectivity.

## Basic Usage

```
gossl serve
```

Starts on `0.0.0.0:8443` using a certificate auto-generated from the default database.

## Response Format

The server streams the request body back as the response body. With `-v`, all request headers are also set on the response.

```bash
# Body is echoed back
curl -k -d "hello" https://localhost:8443/
# → hello

# With verbose, request headers appear on the response
curl -k -v -H "X-Custom: test" https://localhost:8443/
# Response includes X-Custom: test header
```

## Modes

### Database mode (default)

The server loads its certificate and key from the database. A certificate is created automatically if one does not exist.

```
gossl serve --db gossl.db --dn "server.example.com"
```

`--dn` specifies the CN used when auto-generating a certificate.

### File mode

Provide certificate and key files directly, bypassing the database:

```
gossl serve --cert server.pem --pkey server-key.pem
```

## Options

| Flag | Default | Description |
|------|---------|-------------|
| `--db` | `gossl.db` | Path to the SQLite database (database mode) |
| `--dn` | `localhost` | CN for auto-generated server certificate |
| `--cert` | (none) | PEM certificate file (file mode) |
| `--pkey` | (none) | PEM private key file (file mode) |
| `--port` | `8443` | Port to listen on |
| `--addr` | `0.0.0.0` | Address to bind to |
| `--metrics-handler` | `/metrics` | Path for Prometheus metrics endpoint (set to empty string to disable) |
| `--mtls` | false | Require client certificates |
| `-v` | false | Copy request headers to response headers |

## mTLS

Enable mutual TLS to require and verify client certificates:

```
gossl serve --mtls --db gossl.db
```

The server uses the CAs in the database as the trusted client CA pool. Clients that do not present a certificate, or present one signed by an unknown CA, are rejected at the TLS layer.

## Metrics

The server exposes Prometheus-compatible metrics via OpenTelemetry at the `/metrics` endpoint (configurable with `--metrics-handler`).

```
curl -k https://localhost:8443/metrics
```

Available metrics:

| Metric | Type | Description |
|--------|------|-------------|
| `gossl_conn_setup_duration_nanoseconds` | Histogram | Time from new connection to first active state (TLS handshake latency) |

Disable the endpoint by setting `--metrics-handler ""`.

## Typical Workflows

### Test a certificate chain end to end

```
# Create PKI
gossl ca create --cn "Test Root CA"
gossl cert issue --cn "server.localhost" --san "DNS:localhost,IP:127.0.0.1"

# Start server
gossl serve --dn "server.localhost"

# Inspect from another terminal
gossl sclient localhost:8443 --ca-file <(gossl cert export --serial <root-serial>)
curl -k https://localhost:8443/test
```

### Test mTLS client authentication

```
# Issue a client certificate
gossl cert issue --cn "client.test" --ca "Test Root CA"

# Start server with mTLS
gossl serve --mtls --db gossl.db

# Connect with client cert
gossl sclient localhost:8443 --cert client.pem --key client-key.pem
curl --cert client.pem --key client-key.pem --cacert root.pem https://localhost:8443/
```

### Bind to loopback only

```
gossl serve --addr 127.0.0.1 --port 9443
```
