# Getting Started

## Installation

Build from source using Bazel:

```
bazel build //cmd/gossl
```

The binary is written to `bazel-bin/cmd/gossl/gossl`. Add it to your PATH or invoke it directly.

## Quick Start

### 1. Create a CA

```
gossl ca create --cn "My Root CA"
```

This creates `gossl.db` in the current directory and registers the root CA. The first CA created is always the root.

### 2. Issue a Certificate

```
gossl cert issue --cn "server.example.com" --san "DNS:server.example.com,IP:127.0.0.1"
```

Without `--ca`, the cert is issued under the root CA. Output is PEM to stdout.

### 3. Inspect a Remote Server

```
gossl sclient server.example.com:443
```

Connects to the host, performs a TLS handshake, and prints certificate details for the server's chain.

### 4. Verify a Certificate File

```
gossl cert inspect server.pem
```

Prints the subject, issuer, validity period, SANs, and key info from a local PEM file.

## The Database

gossl stores all CA and certificate state in a single SQLite file. The default is `gossl.db` in the current working directory. Every command that reads or writes PKI state accepts `--db` to point at a different file.

```
gossl ca create --cn "Prod Root CA" --db /etc/pki/prod.db
gossl cert issue --cn "api.prod.example.com" --db /etc/pki/prod.db
```

The database contains:
- A unified CA table where root CAs have `parent_id = NULL` and intermediates reference their parent.
- A certificate table with serial numbers, PEM data, and revocation status.

Keep the database file backed up. Losing it means losing the ability to sign or revoke certificates under those CAs.

## Output Format

Private keys are written in PEM format. RSA keys use PKCS#1 encoding; ECDSA keys use SEC 1 encoding. Certificates are standard PEM X.509.

Most commands write PEM to stdout unless `--out` is provided.
