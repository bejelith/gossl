# Key Inspect & Cert Inspect Public Key Fingerprint

## Summary

Add a `gossl key inspect` command to display private key details including a SHA-256 public key fingerprint. Add the same fingerprint to `gossl cert inspect` output so users can visually match a key to a certificate.

## Motivation

Verifying that a private key matches a certificate is one of the most common mTLS troubleshooting tasks. With openssl, this requires running two separate commands and comparing modulus output manually. gossl should make this a one-glance operation: run `key inspect` and `cert inspect`, compare the `Public Key SHA256` line.

## Commands

### `gossl key inspect <file|->` (new)

Parses a PEM-encoded private key file (or stdin with `-`) and prints:

```
Algorithm:         RSA
Key Size:          4096 bits
Public Key SHA256: ab:cd:ef:12:34:56:78:...
```

For ECDSA keys:

```
Algorithm:         ECDSA
Curve:             P-256
Public Key SHA256: ab:cd:ef:12:34:56:78:...
```

With `--raw`, appends the full public key material:

- RSA: `Modulus: <hex>` (the RSA modulus N in uppercase hex with colon separators)
- ECDSA: `Public Point: <hex>` (uncompressed EC point in hex with colon separators)

#### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--raw` | false | Show full modulus or public point in hex |

#### Input

- Positional arg: file path or `-` for stdin
- Accepts PEM types: `RSA PRIVATE KEY` (PKCS#1), `EC PRIVATE KEY` (SEC 1)

### `gossl cert inspect` (modified)

Add one line to the existing output, after the `Public Key:` line:

```
Public Key SHA256: ab:cd:ef:12:34:56:78:...
```

Uses the same fingerprint computation as `key inspect`, so the values are directly comparable.

## Implementation

### Shared helpers in `crypto.go`

- `publicKeyFingerprint(pub any) string` — DER-encodes the public key with `x509.MarshalPKIXPublicKey`, computes SHA-256, formats as colon-separated lowercase hex prefixed with `SHA256:`.
- `publicKeyRaw(pub any) string` — returns the raw public key material as colon-separated uppercase hex. For RSA, this is the modulus bytes. For ECDSA, this is the uncompressed EC point (`elliptic.Marshal`).

### New file: `internal/cli/key.go`

- `newKeyCmd()` — returns `key` command group, adds `inspect` subcommand.
- `newKeyInspectCmd()` — defines the `inspect` command with `--raw` flag.
- `runKeyInspect(args []string, raw bool)` — reads PEM from file/stdin, calls `parsePrivateKey`, extracts public key, prints fields.
- `printKeyInfo(priv any, raw bool)` — formats and prints key details.

### Modified: `internal/cli/root.go`

Register `newKeyCmd()` on the root command.

### Modified: `internal/cli/cert.go`

In `printCertInfo`, add `publicKeyFingerprint(cert.PublicKey)` output after the existing `Public Key:` line.

### Build files

Run gazelle to regenerate BUILD.bazel files after adding `key.go`.

## Testing

Table-driven tests for:
- `publicKeyFingerprint` with RSA and ECDSA keys — verify deterministic output.
- `publicKeyRaw` with RSA and ECDSA keys — verify correct hex encoding.
- `key inspect` command with RSA and ECDSA PEM files, with and without `--raw`.
- `cert inspect` output includes `Public Key SHA256:` line.
- Matching: generate a keypair and cert, verify the fingerprint lines are identical.
