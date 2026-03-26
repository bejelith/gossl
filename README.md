# gossl

A simplified alternative to openssl for engineers working with mTLS-enabled services.

mTLS is used to authorize requests by trusting the identity associated with the peer certificate. Engineers need effective tools to troubleshoot customer authentication issues — incorrect CSRs, expired certificates, missing intermediates in TLS handshakes that prevent chain-of-trust verification. They also need to manage test CAs for backend system testing. Today, openssl handles this but is overcomplicated and hard to use for newcomers.

gossl replaces the most common openssl workflows with a single binary backed by a single SQLite file. It offers a command-line interface for scripting and a terminal UI for interactive CA management.

## Problems we're trying to solve

We struggle with engineers not being able to troubleshoot mTLS issues and general TLS thoroubleshooting, few really understand and/or read the TLS protocol so we had to invest into a lot of OpenSSL wrapper tools to help them. OpenSSL does a lot of things really well but it's also really complex and hard to use for newcomers and the documentation is often lacking or confusing.

The other problem what im trying to solve is educational, this tool should help practive and understand basic concepts without the need of knowing the tool specs by leaveraging LLMs.

## Features

### Troubleshooting

Inspect certificates, validate CSRs, verify chains of trust, and probe live servers — from files, stdin, or remote connections.

```bash
# Inspect a certificate
gossl cert inspect cert.pem

# Inspect a private key
gossl key inspect key.pem

# Check if a key matches a cert (compare the Public Key SHA256 line)
gossl cert inspect cert.pem
gossl key inspect key.pem

# Show the full RSA modulus or ECDSA public point
gossl key inspect key.pem --raw

# Verify a certificate against a CA bundle
gossl cert verify --chain ca-bundle.pem cert.pem

# Inspect a CSR
gossl csr inspect request.csr

# Check a live server's TLS configuration
gossl sclient api.example.com:443

# Read from stdin
cat cert.pem | gossl cert inspect -
```

### Test CA Management

Create and manage a full CA hierarchy (root CA, intermediates, leaf certs) stored in a single SQLite file.

```bash
# Create a root CA (initializes the database)
gossl ca create --cn "Test Root CA" --db myca.db

# Create an intermediate CA
gossl intermediate create --cn "Staging Intermediate" --db myca.db

# Issue a leaf certificate
gossl cert issue --cn "api.example.com" --intermediate "Staging Intermediate" --san "api.example.com,api.internal" --db myca.db

# List certificates
gossl cert list --db myca.db

# Export a certificate (with full chain)
gossl cert export --serial A1B2C3D4 --chain --db myca.db --out client.pem

# Export a private key by certificate common name
gossl key export --cn "api.example.com" --db myca.db --out key.pem

# Revoke a certificate
gossl cert revoke --serial A1B2C3D4 --db myca.db
```

### Echo Server

Start an HTTPS echo server that streams the request body back. Exposes Prometheus metrics at `/metrics` with TLS handshake latency histograms.

```bash
# Serve using a cert from the DB
gossl serve --db myca.db --dn "api.example.com"

# Serve using cert/key files
gossl serve --cert cert.pem --pkey key.pem

# Require client certs (mTLS) and echo request headers
gossl serve --db myca.db --dn "api.example.com" --mtls -v --port 8443

# Scrape metrics
curl -k https://localhost:8443/metrics
```

### CA Hierarchy Visualization

Generate a diagram of all CAs and certificates in a database.

```bash
# SVG diagram (default)
gossl graph

# Text tree to stdout
gossl graph --format text --out /dev/stdout

# JSON tree
gossl graph --format json --out /dev/stdout

# Filter to CAs only (no leaf certs)
gossl graph --filter ca,intermediate --format text --out /dev/stdout
```

Output formats: `svg` (color-coded tree diagram), `json` (nested tree), `text` (ASCII tree).

### Terminal UI (planned)

> Not yet implemented. See [Future Work](#future-work).

Interactive terminal UI for browsing and managing your CA hierarchy.

## Using gossl with LLMs

gossl embeds its full documentation and can dump it as context for any LLM.

### Claude Code

```bash
# Give Claude full gossl context, then ask a question
gossl docs | claude "I have two services that need mTLS. Walk me through setting up a CA hierarchy and issuing certs for both."

# Or use it interactively — paste the docs into the conversation
gossl docs | pbcopy  # macOS
```

### In a Claude Code session

```
> ! gossl docs > /tmp/gossl-docs.md
> Read /tmp/gossl-docs.md and help me troubleshoot why my client cert is being rejected by nginx
```

### Single topic

```bash
gossl docs sclient | claude "explain what each field in the output means"
gossl docs certificates | claude "how do I sign an external CSR?"
```

### Example: Multi-region mTLS simulation with Claude Code

The following prompt demonstrates using Claude Code with `gossl docs` to build and validate a realistic mTLS hierarchy. Paste it into a Claude Code session:

```
Run `gossl docs` to learn how the tool works, then:

1. Create a root CA.
2. Create 3 regional intermediates: US, Canada, Mexico.
3. Under US, create sub-intermediates: us-east-1, us-east-2, us-west-1.
   Under Canada and Mexico, create a single sub-intermediate: main-district.
4. For each sub-intermediate, issue a client cert and a server cert with
   associated private key.
5. Verify that a client cert issued under us-west-1 CANNOT connect to a
   server using a cert issued under us-east-1 (different trust boundaries).
6. Verify that a client cert issued under us-east-1 CAN connect to a server
   using a cert issued directly under the US intermediate (shared ancestor).

Use gossl for all certificate operations.
```

This exercises the full CA hierarchy, cross-intermediate trust boundaries, and mTLS verification — all driven by an LLM reading gossl's embedded docs.

## Installation

```bash
curl -sL https://raw.githubusercontent.com/bejelith/gossl/master/install.sh | bash
```

Or build from source:

```bash
bazel build //cmd/gossl
```

## Development

### Prerequisites

- [Bazel](https://bazel.build/) 9+
- [pre-commit](https://pre-commit.com/)

### Build

```bash
bazel build //...
```

### Test

```bash
# Unit tests
bazel test //...

# Integration tests (requires Docker)
bazel test //... --test_tag_filters=integration
```

### Format

```bash
bazel run //tools/format:format
```

### Setup

```bash
pre-commit install
```

## Future Work

- **Full X.509 Subject field support** — Currently only Common Name (`--cn`) is supported. Add flags for Organization (`--o`), Organizational Unit (`--ou`), Country (`--c`), State (`--st`), Locality (`--l`), and other standard Subject fields for CA and certificate creation.
- **Custom OID extensions** — Support adding arbitrary OID codes and values to certificates and CSRs (e.g. `--ext 1.2.3.4.5=value`), enabling custom certificate policies, proprietary extensions, and compliance with organization-specific PKI requirements.
- **Configurable key usage and extended key usage** — Allow specifying `--key-usage` (e.g. `digitalSignature,keyEncipherment`) and `--ext-key-usage` (e.g. `serverAuth,clientAuth,codeSigning`) flags on certificate creation and CSR signing, instead of using hardcoded defaults.
- **Charm terminal UI** — Interactive terminal UI (`gossl ui --db myca.db`) built with [Bubble Tea](https://github.com/charmbracelet/bubbletea) for browsing and managing the CA hierarchy, issuing certificates, and inspecting the trust chain visually.
- **CI pipeline for pull requests** — GitHub Actions workflow that runs `bazel test //...` on every PR and triggers AI-powered code review using Claude Code agents with the code-review skills.
- **Remote Bazel cache** — Set up remote caching (e.g. [BuildBuddy](https://www.buildbuddy.io/) free tier or [EngFlow](https://www.engflow.com/)) to speed up CI builds and share cache between developers.
- **CI test log archiving** — Upload Bazel test logs (`bazel-testlogs/`) as GitHub Actions artifacts on failure so they can be downloaded and inspected after a failed run.
- **ACME server** — Embed an ACME (RFC 8555) server that issues certificates from any intermediate CA in the database, enabling automated cert provisioning for test environments using standard ACME clients like certbot or Caddy.
- **Encryption-at-rest for private keys** — Private keys are currently stored as plaintext PEM in the SQLite database. A passphrase-based encryption layer or OS keychain integration would protect key material if the database file is compromised.
