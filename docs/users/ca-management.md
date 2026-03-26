# CA Management

## Creating a Root CA

```
gossl ca create --cn "My Root CA"
```

The first CA created in a database is the root. It has no parent (`parent_id = NULL`). A self-signed certificate is generated and stored in the database.

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--cn` | required | Common name for the CA |
| `--db` | `gossl.db` | Path to the SQLite database |
| `--days` | 3650 | Certificate validity in days |
| `--key-algo` | `rsa` | Key algorithm: `rsa` or `ecdsa` |
| `--key-size` | `2048` | RSA key size in bits |
| `--curve` | `P-256` | ECDSA curve: `P-256`, `P-384`, `P-521` |
| `--ca` | (none) | Parent CA common name (see intermediates) |

## Creating an Intermediate CA

After a root CA exists, run `ca create` again. Without `--ca`, the new CA is parented to the root automatically.

```
gossl ca create --cn "Issuing CA"
```

To explicitly specify a parent:

```
gossl ca create --cn "Leaf Issuing CA" --ca "Issuing CA"
```

The intermediate's certificate is signed by the specified parent CA and stored in the database.

## Hierarchy Examples

### Two-tier (root + issuing)

```
gossl ca create --cn "Root CA" --days 7300
gossl ca create --cn "Issuing CA" --days 3650
```

Issue certificates from the intermediate:

```
gossl cert issue --cn "service.example.com" --ca "Issuing CA"
```

### Three-tier (root + policy + issuing)

```
gossl ca create --cn "Root CA" --days 7300
gossl ca create --cn "Policy CA" --ca "Root CA" --days 3650
gossl ca create --cn "Issuing CA" --ca "Policy CA" --days 1825
gossl cert issue --cn "service.example.com" --ca "Issuing CA"
```

### ECDSA hierarchy

```
gossl ca create --cn "EC Root CA" --key-algo ecdsa --curve P-384
gossl ca create --cn "EC Issuing CA" --key-algo ecdsa --curve P-256
```

## Listing CAs

```
gossl ca list
gossl ca list --db /path/to/other.db
```

Prints each CA's common name, serial, expiry, and parent (if any).
