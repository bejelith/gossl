# Troubleshooting

## Private Key Does Not Match Certificate

**Symptom:** TLS server fails to start, or handshake fails with `private key does not match public key` or similar error.

**Fix:** Verify the key and certificate are a pair by comparing their public key fingerprints:

```
gossl cert inspect cert.pem
gossl key inspect key.pem
```

If the `Public Key SHA256` lines differ, the key and certificate do not match. Export the correct key from the database:

```
gossl key export --cn "server.example.com" --out key.pem
```

## mTLS: Client Certificate Rejected

**Symptom:** TLS handshake fails with `certificate required`, `bad certificate`, or `unknown CA`.

**Causes and fixes:**

1. The client certificate was not signed by a CA that the server trusts. Confirm the server is using a trust store that includes the issuing CA. In gossl serve, the trusted pool comes from the database — ensure the client cert was issued by a CA in that database.

2. The client is not presenting a certificate at all. Check that `--cert` and `--key` are passed to the connecting tool.

3. The client certificate has been revoked. Check `gossl cert list` and look for `revoked` status on the relevant serial.

## Expired Certificate

**Symptom:** TLS error `certificate has expired` or `x509: certificate has expired or is not yet valid`.

**Fix:** Issue a new certificate:

```
gossl cert issue --cn "service.example.com" --san "DNS:service.example.com" --ca "Issuing CA"
```

Check expiry of any certificate:

```
gossl cert inspect service.pem
gossl cert inspect --db gossl.db --serial 0A1B2C3D
```

Check expiry of CA certificates:

```
gossl ca list
```

## Missing Intermediate CA

**Symptom:** Chain validation fails even though the end-entity certificate is valid.

**Symptom detail:** `x509: certificate signed by unknown authority` when the root is trusted but an intermediate is not in the presented chain.

**Fix:** Export the full chain and use it when serving or connecting:

```
gossl cert export --serial <end-entity-serial> --chain --out fullchain.pem
```

Verify the chain is complete:

```
gossl cert verify fullchain.pem
```

## Wrong CA Trust Store

**Symptom:** `gossl sclient` or a browser reports `certificate signed by unknown authority` against an internal server.

**Fix:** Pass the correct root CA to the client:

```
gossl sclient internal.corp:8443 --ca-file root-ca.pem
```

Export the root CA certificate from the database:

```
gossl cert export --serial <root-ca-serial> --out root-ca.pem
```

The root CA serial is visible in `gossl ca list`.

## Weak Key in CSR Rejected

**Symptom:** `gossl cert sign` fails with a message about key strength.

**Cause:** `cert sign` enforces a minimum RSA key size of 2048 bits. CSRs with 1024-bit RSA keys are rejected.

**Fix:** Regenerate the CSR with a stronger key:

```
openssl genrsa -out key.pem 2048
openssl req -new -key key.pem -subj "/CN=example.com" -out request.csr
gossl cert sign request.csr --ca "Issuing CA"
```

Inspect the key size in an existing CSR before signing:

```
gossl csr inspect request.csr
```

## SNI Mismatch

**Symptom:** Server presents a certificate for the wrong hostname, or `gossl sclient` shows a certificate whose subject does not match the host you connected to.

**Cause:** The server is returning a default certificate because the SNI hostname in the ClientHello did not match any configured virtual host, or the certificate simply has the wrong SANs.

**Fix — if connecting by IP:** Override SNI to send the expected hostname:

```
gossl sclient 10.0.0.5:443 --sni api.example.com
```

**Fix — if the certificate is missing SANs:** Reissue with correct SANs:

```
gossl cert issue --cn "api.example.com" \
  --san "DNS:api.example.com,DNS:api-internal.example.com" \
  --ca "Issuing CA"
```

Note: Modern TLS stacks match on SANs, not CN. Always include `DNS:` entries in `--san`.

## Connection Timeout / Hang

**Symptom:** `gossl sclient` hangs indefinitely.

**Fix:** Set an explicit timeout:

```
gossl sclient host:443 --timeout 5s
```

Check that the port is reachable and not firewalled before debugging TLS.

## Certificate Issued but Not Visible in List

**Symptom:** `gossl cert list` does not show a certificate just issued.

**Cause:** A different database file was used for issuance and listing.

**Fix:** Always pass `--db` consistently, or rely on the same working directory when using the default `gossl.db`:

```
gossl cert issue --cn "example.com" --db /path/to/pki.db
gossl cert list --db /path/to/pki.db
```
