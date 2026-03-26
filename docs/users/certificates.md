# Certificates

## Issuing a Certificate

```
gossl cert issue --cn "server.example.com" --san "DNS:server.example.com,IP:192.168.1.10"
```

Without `--ca`, the cert is signed by the root CA. PEM output goes to stdout.

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--cn` | required | Common name |
| `--ca` | root CA | Signing CA common name |
| `--db` | `gossl.db` | Path to the SQLite database |
| `--days` | 365 | Validity in days |
| `--san` | (none) | Subject alternative names (comma-separated) |
| `--key-algo` | `rsa` | Key algorithm: `rsa` or `ecdsa` |
| `--key-size` | `2048` | RSA key size in bits |
| `--curve` | `P-256` | ECDSA curve |

SAN format: `DNS:hostname`, `IP:1.2.3.4`, `EMAIL:user@example.com`, `URI:https://example.com`

```
gossl cert issue \
  --cn "api.example.com" \
  --ca "Issuing CA" \
  --san "DNS:api.example.com,DNS:api-internal.example.com,IP:10.0.0.5" \
  --days 90
```

## Signing an External CSR

Sign a CSR generated outside gossl:

```
gossl cert sign request.csr --ca "Issuing CA" --days 365
```

Write the signed certificate to a file:

```
gossl cert sign request.csr --ca "Issuing CA" --out signed.pem
```

Overwrite an existing output file:

```
gossl cert sign request.csr --ca "Issuing CA" --out signed.pem --force
```

### Key Strength Validation

`cert sign` validates the key in the CSR before signing. RSA keys must be at least 2048 bits. CSRs with weaker keys are rejected.

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--ca` | root CA | Signing CA common name |
| `--db` | `gossl.db` | Path to the SQLite database |
| `--days` | 365 | Validity in days |
| `--out` | stdout | Output file path |
| `--force` | false | Overwrite existing output file |

## Listing Certificates

```
gossl cert list
gossl cert list --db /path/to/other.db
```

Prints serial, common name, CA, expiry, and revocation status for every certificate in the database.

## Revoking a Certificate

```
gossl cert revoke --serial 0A1B2C3D
```

Marks the certificate as revoked in the database. The serial is the hex serial number shown in `cert list` or `cert inspect`.

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--serial` | required | Hex serial number of the certificate |
| `--db` | `gossl.db` | Path to the SQLite database |

## Exporting a Certificate

Retrieve a certificate from the database by serial number:

```
gossl cert export --serial 0A1B2C3D
```

Write to a file:

```
gossl cert export --serial 0A1B2C3D --out cert.pem
```

Include the full chain (certificate + all intermediate CA certs up to root):

```
gossl cert export --serial 0A1B2C3D --out chain.pem --chain
```

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--serial` | required | Hex serial number |
| `--db` | `gossl.db` | Path to the SQLite database |
| `--out` | stdout | Output file path |
| `--chain` | false | Include full certificate chain |
| `--force` | false | Overwrite existing output file |

## Inspecting a Certificate

From a file:

```
gossl cert inspect server.pem
```

From stdin:

```
cat server.pem | gossl cert inspect -
openssl s_client -connect host:443 </dev/null | gossl cert inspect -
```

From the database by serial:

```
gossl cert inspect --db gossl.db --serial 0A1B2C3D
```

Prints subject, issuer, serial, validity dates, key algorithm and size, SANs, public key SHA-256 fingerprint, and basic constraints.

The `Public Key SHA256` line can be compared with the output of `gossl key inspect` to verify that a certificate and private key match.

## Verifying a Certificate

Check that a certificate is valid against a chain:

```
gossl cert verify server.pem
gossl cert verify server.pem --chain chain.pem
cat server.pem | gossl cert verify -
```

`--chain` provides intermediate or root certs to build the trust path. Without it, only the certificate's self-consistency is checked.
