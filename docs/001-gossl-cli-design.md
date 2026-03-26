# gossl CLI Design Spec

## Overview

gossl is a simplified alternative to openssl for engineers working with mTLS-enabled services. It provides two core capabilities:

1. **Troubleshooting** — inspect certs, CSRs, verify chains, probe live servers
2. **Test CA management** — create and manage a CA hierarchy (root CA, intermediates, leaf certs) backed by a single SQLite file

The tool offers a Cobra-based CLI for text commands and a Bubble Tea TUI for interactive CA management.

## Architecture

```
cmd/gossl/              # binary entry point (thin — no business logic)
internal/
  ca/                   # CA + intermediate creation, cert issuance/revocation
  cert/                 # x509 parsing, inspection, chain verification
  csr/                  # CSR parsing + validation
  tls/                  # remote server probing (TLS handshake, chain retrieval)
  store/
    certstore/          # SQLite — certs, CAs, intermediates, metadata
    keystore/           # KV API — private keys (SQLite-backed for now)
```

### Layer Rules

- **CLI/TUI are thin.** They parse input and call into `internal/` packages. No business logic in `cmd/`.
- **Packages are independent.** `cert` does not import `ca`. `ca` imports `cert` and `store`.
- **Store is behind interfaces.** `certstore` and `keystore` interfaces are defined in `internal/ca/` (consumer side), implemented in `internal/store/`.
- **Nothing is exported.** All packages live under `internal/`. This is a CLI tool, not a library.

## Command Surface

### CA Management (DB-backed)

| Command | Key Flags | Description |
|---|---|---|
| `gossl ca create` | `--cn`, `--db`, `--days`, `--key-algo`, `--key-size`, `--curve` | Create root CA, initialize DB file |
| `gossl ca list` | `--db` | Show root CA info |
| `gossl intermediate create` | `--cn`, `--db`, `--days`, `--key-algo`, `--key-size`, `--curve` | Create intermediate signed by root CA |
| `gossl intermediate list` | `--db` | List all intermediates |
| `gossl cert issue` | `--cn`, `--db`, `--intermediate`, `--days`, `--san`, `--key-algo`, `--key-size`, `--curve` | Issue cert signed by an intermediate |
| `gossl cert list` | `--db` | List all issued certs |
| `gossl cert revoke` | `--serial`, `--db` | Mark cert as revoked |
| `gossl cert export` | `--serial`, `--db`, `--out`, `--chain`, `--force` | Export cert PEM to file (optionally full chain) |

### Key Management

| Command | Key Flags | Description |
|---|---|---|
| `gossl key inspect` | `<file\|->`, `--raw` | Display private key details: algorithm, size/curve, public key SHA-256 fingerprint. `--raw` shows full modulus (RSA) or public point (ECDSA) |
| `gossl key export` | `--cn`, `--db`, `--out`, `--force` | Export private key from database by certificate common name |

### Troubleshooting (file / stdin / remote)

| Command | Args / Flags | Description |
|---|---|---|
| `gossl cert inspect` | `<file\|->`, `--db --serial` | Display cert details: subject, issuer, SANs, expiry, key algo, public key SHA-256 fingerprint |
| `gossl cert verify` | `<file\|->`, `--chain <ca-bundle-file>` | Verify cert against a CA bundle file, report errors |
| `gossl csr inspect` | `<file\|->` | Display CSR details |
| `gossl server check` | `<host:port>`, `--sni`, `--timeout`, `--ca-file`, `--db` | Connect, show cert chain, verify trust, flag issues |

### Echo Server

| Command | Key Flags | Description |
|---|---|---|
| `gossl serve` | `--db`, `--dn`, `--port`, `--mtls`, `-v` | Start HTTPS echo server using cert from DB (by common name) |
| `gossl serve` | `--cert`, `--pkey`, `--port`, `--mtls`, `-v` | Start HTTPS echo server using cert/key files |

- `--db`/`--dn` and `--cert`/`--pkey` are mutually exclusive flag groups.
- `--dn` matches against cert common names in the DB.
- Default port: 8443.
- Without `--mtls`: accepts client certs if offered, does not require them.
- With `--mtls`: requires and verifies client cert against the CA chain in `--db` (or system trust store for file mode).
- Response body: URI, form data, body. With `-v`: also includes request headers.
- If a client presents a cert, the response always includes parsed peer cert info (subject, issuer, serial, expiry).

### TUI

| Command | Flags | Description |
|---|---|---|
| `gossl ui` | `--db` | Launch Bubble Tea TUI for interactive CA management |

### Input Conventions

- All DB commands default to `--db gossl.db` in the current directory if not specified.
- Stdin is indicated by `-` or absence of a file arg when piped.
- `--key-algo` supports `rsa` (default) and `ecdsa`.
- `--key-size` defaults: RSA 4096. Ignored for ECDSA.
- `--curve` defaults: P-256. Ignored for RSA.
- `--days` defaults: CA 3650 (10 years), intermediate 1825 (5 years), cert 365 (1 year).
- `--timeout` defaults: 10s for `server check`.
- `--force` on export overwrites existing files. Without it, export fails if file exists.
- Output format is PEM. RSA keys use PKCS#1 encoding. ECDSA keys use SEC 1 (EC PRIVATE KEY PEM block).
- Serial numbers are uppercase hex without colons (e.g., `A1B2C3D4`).

## Storage

### SQLite Schema (certstore)

One root CA per database. Multiple intermediates per CA. Multiple certs per intermediate.

Schema version is tracked via SQLite `user_version` pragma. On open, gossl checks the version and refuses to open a mismatched DB with a clear error message. No automatic migrations in v1.

```sql
PRAGMA user_version = 1;

CREATE TABLE ca (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    common_name TEXT NOT NULL,
    serial      TEXT NOT NULL UNIQUE,
    key_algo    TEXT NOT NULL,
    cert_pem    TEXT NOT NULL,
    not_before  DATETIME NOT NULL,
    not_after   DATETIME NOT NULL,
    created_at  DATETIME NOT NULL
);

CREATE TABLE intermediate (
    id          INTEGER PRIMARY KEY,
    ca_id       INTEGER NOT NULL REFERENCES ca(id),
    common_name TEXT NOT NULL,
    serial      TEXT NOT NULL UNIQUE,
    key_algo    TEXT NOT NULL,
    cert_pem    TEXT NOT NULL,
    not_before  DATETIME NOT NULL,
    not_after   DATETIME NOT NULL,
    created_at  DATETIME NOT NULL
);

CREATE TABLE cert (
    id              INTEGER PRIMARY KEY,
    intermediate_id INTEGER NOT NULL REFERENCES intermediate(id),
    common_name     TEXT NOT NULL,
    serial          TEXT NOT NULL UNIQUE,
    key_algo        TEXT NOT NULL,
    cert_pem        TEXT NOT NULL,
    not_before      DATETIME NOT NULL,
    not_after       DATETIME NOT NULL,
    revoked_at      DATETIME,
    created_at      DATETIME NOT NULL
);
```

### KeyStore (KV API)

Private keys are stored separately behind a KV interface to allow future migration to Vault, KMS, or HSM.

```go
type KeyStore interface {
    Store(ctx context.Context, id string, keyPEM []byte) error
    Load(ctx context.Context, id string) ([]byte, error)
    Delete(ctx context.Context, id string) error
}
```

Keys are referenced by the serial number of the associated cert/CA/intermediate. The initial SQLite implementation uses a `(id TEXT PRIMARY KEY, key_pem BLOB)` table in the same DB file.

`Delete` exists on the interface for future key rotation/destruction workflows. No CLI command calls it in v1.

### Code Generation

SQL queries are written in `.sql` files and compiled to Go code using sqlc. sqlc runs as a Bazel build step via multitool — generated code is not committed to the repository.

```
internal/store/
  schema.sql      # CREATE TABLE statements
  queries.sql     # named queries
  sqlc.yaml       # sqlc configuration
```

## Dependencies

| Dependency | Purpose |
|---|---|
| `github.com/spf13/cobra` | CLI command routing, flags, shell completions |
| `github.com/charmbracelet/bubbletea` | TUI framework |
| `github.com/charmbracelet/bubbles` | TUI components (tables, text inputs) |
| `github.com/charmbracelet/lipgloss` | TUI styling |
| `modernc.org/sqlite` | Pure-Go SQLite driver (no CGO) |
| `sqlc` (build tool) | SQL-to-Go code generation |

Pure-Go SQLite (`modernc.org/sqlite`) is chosen over `mattn/go-sqlite3` to avoid CGO. This keeps the Bazel build hermetic and simplifies cross-compilation.

## Error Handling

### Library Errors (internal/)

Typed sentinel errors that callers can inspect:

```go
var (
    ErrExpired         = errors.New("certificate has expired")
    ErrChainIncomplete = errors.New("chain of trust is incomplete")
    ErrInvalidCSR      = errors.New("invalid certificate signing request")
)
```

Errors are wrapped with context: `fmt.Errorf("verifying %s: %w", cn, ErrChainIncomplete)`

### CLI Exit Codes

| Exit Code | Meaning |
|---|---|
| 0 | Success |
| 1 | General error (bad flags, file not found) |
| 2 | Cert validation failure (expired, bad chain, invalid CSR) |
| 3 | DB error (corrupt, missing, schema mismatch) |

No panics. All errors are returned and handled at the Cobra command level.

## Out of Scope (v1)

- CRL generation / OCSP responder
- Automatic schema migrations
- PKCS#12 / DER output formats
- Key rotation / destruction CLI commands

## Testing

### Unit Tests (target: 80%+ coverage)

- `internal/cert/` — parse, inspect, verify against fixture PEM files in `testdata/`
- `internal/csr/` — parse, validate against fixture CSR files in `testdata/`
- `internal/ca/` — cert issuance and revocation using in-memory SQLite
- `internal/store/` — CRUD operations against in-memory SQLite
- `internal/tls/` — mock `net.Conn` for TLS handshake parsing

### Integration Tests (complete coverage)

- `internal/tls/` — testcontainers running nginx/envoy with mTLS, verify `server check` against real TLS endpoints
- End-to-end CLI tests — run the `gossl` binary, create CA, issue certs, inspect, verify chains, check against testcontainer servers

### Test Conventions

- Unit tests colocated with source: `foo_test.go` next to `foo.go`
- Table-driven tests with descriptive failure messages: `Foo(%q) = %d, want %d`
- Integration tests tagged with `//go:build integration` and a separate Bazel test target
- `bazel test //...` runs unit tests by default
- `bazel test //... --test_tag_filters=integration` runs integration tests
- External dependencies provisioned via testcontainers-go (no mocking infrastructure)
