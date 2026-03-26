# Private Keys

## Inspecting a Private Key

From a file:

```
gossl key inspect key.pem
```

From stdin:

```
cat key.pem | gossl key inspect -
```

Output for an RSA key:

```
Algorithm:         RSA
Key Size:          2048 bits
Public Key SHA256: SHA256:ab:cd:ef:12:34:56:78:...
```

Output for an ECDSA key:

```
Algorithm:         ECDSA
Curve:             P-256
Public Key SHA256: SHA256:ab:cd:ef:12:34:56:78:...
```

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--raw` | false | Show full modulus (RSA) or public point (ECDSA) in hex |

With `--raw`, an additional line is printed:

- RSA: `Modulus: <colon-separated uppercase hex>`
- ECDSA: `Public Point: <colon-separated uppercase hex>`

## Exporting a Private Key

Export the private key for a certificate by common name:

```
gossl key export --cn "server.example.com"
```

Write to a file:

```
gossl key export --cn "server.example.com" --out key.pem
```

Overwrite an existing file:

```
gossl key export --cn "server.example.com" --out key.pem --force
```

Without `--out`, the PEM key is written to stdout.

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--cn` | required | Certificate common name |
| `--db` | `gossl.db` | Path to the SQLite database |
| `--out` | stdout | Output file path |
| `--force` | false | Overwrite existing output file |

## Verifying a Key Matches a Certificate

Both `gossl key inspect` and `gossl cert inspect` print a `Public Key SHA256` line. If the fingerprints match, the key and certificate are a pair.

```
gossl cert inspect cert.pem
gossl key inspect key.pem
```

Compare the `Public Key SHA256` lines — if they are identical, the key matches the certificate.
