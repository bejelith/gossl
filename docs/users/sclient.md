# TLS Client Inspection (sclient)

`gossl sclient` connects to a TLS server, completes a handshake, and reports the server's certificate chain. It is similar in purpose to `openssl s_client`.

## Basic Usage

```
gossl sclient host:port
```

Examples:

```
gossl sclient example.com:443
gossl sclient internal-service.corp:8443
```

## Options

| Flag | Default | Description |
|------|---------|-------------|
| `--sni` | (host from argument) | Override the TLS SNI hostname sent in the handshake |
| `--timeout` | 10s | Connection timeout |
| `--ca-file` | system trust store | PEM file of CA certificates to trust |
| `--show-certs` | false | Print full PEM blocks for all certificates in the chain |
| `--cert` | (none) | Client certificate for mTLS (PEM file) |
| `--key` | (none) | Client private key for mTLS (PEM file) |
| `--alpn` | (none) | Comma-separated list of ALPN protocol names to advertise |

## Examples

### Inspect a public server

```
gossl sclient example.com:443
```

### Override SNI (e.g., when connecting by IP)

```
gossl sclient 10.0.0.5:443 --sni api.example.com
```

### Trust a private CA

```
gossl sclient internal.corp:8443 --ca-file /etc/pki/corp-root.pem
```

### Print the full certificate chain as PEM

```
gossl sclient example.com:443 --show-certs
```

### Connect with a client certificate (mTLS)

```
gossl sclient server.example.com:8443 --cert client.pem --key client-key.pem
```

### Specify ALPN protocols

```
gossl sclient example.com:443 --alpn "h2,http/1.1"
```

### Short connection timeout

```
gossl sclient slow-host.example.com:443 --timeout 3s
```

## Output

Without `--show-certs`, prints summary information for each certificate in the chain: subject, issuer, validity, and SANs. With `--show-certs`, also emits the PEM blocks, which can be piped directly to `gossl cert inspect -` or saved to a file.

```
gossl sclient example.com:443 --show-certs | gossl cert inspect -
```
