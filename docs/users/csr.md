# CSR Inspection

`gossl csr inspect` parses and displays the contents of a Certificate Signing Request.

## Usage

From a file:

```
gossl csr inspect request.csr
```

From stdin:

```
cat request.csr | gossl csr inspect -
openssl req -new -key key.pem -subj "/CN=example.com" | gossl csr inspect -
```

## Output

Prints:
- Subject (CN and any other attributes present)
- Public key algorithm and key size / curve
- Requested Subject Alternative Names (if present in extensions)
- Signature algorithm

## Notes

gossl does not store CSRs. This command only parses and displays — it does not create, validate, or sign. To sign a CSR against a CA in the database, use `gossl cert sign`.

The `cert sign` command additionally validates key strength (RSA >= 2048 bits) before signing. `csr inspect` will display a weak key without rejecting it.
