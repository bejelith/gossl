# CA Hierarchy Visualization

Generate a diagram of all CAs and certificates in a gossl database.

## Basic Usage

```bash
gossl graph
```

Outputs an SVG file named after the database (e.g. `gossl.svg` for `gossl.db`).

## Options

| Flag | Default | Description |
|------|---------|-------------|
| `--db` | `gossl.db` | Database file path |
| `--out` | `<db>.svg` | Output file path (defaults to db name with format extension) |
| `--format` | `svg` | Output format: `svg`, `json`, `text` |
| `--filter` | (all) | Node types to include (comma-separated: `ca`, `intermediate`, `cert`) |

## Output Formats

### SVG

Color-coded tree diagram:
- Blue: Root CA
- Purple: Intermediate CAs
- Green: Active certificates
- Red: Revoked certificates

```bash
gossl graph
gossl graph --db prod.db --out hierarchy.svg
```

### Text

ASCII tree, suitable for terminal output or piping:

```bash
gossl graph --format text --out /dev/stdout
```

```
Root CA [ROOT]
├── Production
│   ├── Prod US-East
│   │   └── payments.example.com
│   └── api.prod.example.com
└── Staging
    ├── web.staging.example.com [REVOKED]
    └── api.staging.example.com
```

### JSON

Nested tree structure, useful for programmatic consumption or piping to `jq`:

```bash
gossl graph --format json --out /dev/stdout | jq
```

```json
[
  {
    "name": "Root CA",
    "type": "root",
    "serial": "A1B2C3D4",
    "children": [
      {
        "name": "Intermediate",
        "type": "intermediate",
        "serial": "E5F6A7B8",
        "children": [
          { "name": "api.example.com", "type": "cert", "serial": "C9D0E1F2" }
        ]
      }
    ]
  }
]
```

## Filtering

Show only specific node types. Types: `ca` (root CAs), `intermediate`, `cert` (leaf certificates).

```bash
# CAs only — no leaf certs
gossl graph --filter ca,intermediate --format text --out /dev/stdout

# Certs only — parent CAs are included automatically to keep the tree connected
gossl graph --filter cert --format text --out /dev/stdout
```

When filtering, ancestor CAs of visible nodes are always included so the tree remains connected.
