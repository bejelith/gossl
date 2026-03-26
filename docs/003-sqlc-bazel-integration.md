# sqlc + Bazel Integration

## Overview

gossl uses [sqlc](https://sqlc.dev/) to generate type-safe Go code from SQL queries. The sqlc binary runs as a Bazel genrule at build time via [rules_multitool](https://github.com/theoremlp/rules_multitool). No generated code is committed to the repository.

## How It Works

```
queries.sql + migrations/*.sql → sqlc generate → Go source files → go_library
```

1. SQL schema lives in `internal/store/migrations/` (one file per migration)
2. SQL queries live in `internal/store/*.sql` files with sqlc annotations
3. A Bazel `genrule` runs sqlc at build time, generating Go code
4. The generated `.go` files are included in the `go_library` via `:sqlc_generate`

## File Layout

```
internal/store/
  migrations/
    001_init.sql           # DDL schema (CREATE TABLE statements)
  queries.sql              # cert/CA/intermediate queries (sqlc-annotated)
  keystore_queries.sql     # keystore queries (sqlc-annotated)
  db.go                    # DB open/close, schema versioning (hand-written)
  BUILD.bazel              # genrule + go_library + go_test
```

## sqlc Configuration

There is no `sqlc.yaml` file. The Bazel genrule generates it inline:

```yaml
version: "2"
sql:
  - engine: "sqlite"
    queries:
      - "queries.sql"
      - "keystore_queries.sql"
    schema: "migrations/"
    gen:
      go:
        package: "store"
        out: "."
        output_db_file_name: "sqlc_db.go"
        output_models_file_name: "sqlc_models.go"
```

Output filenames use `sqlc_` prefix for `db.go` and `models.go` to avoid conflicting with the hand-written `db.go`.

## Generated Files

sqlc produces these files (not committed, built by Bazel):

| File | Contents |
|---|---|
| `sqlc_db.go` | `DBTX` interface, `Queries` struct, `New()` constructor |
| `sqlc_models.go` | Go structs for each table: `Ca`, `Intermediate`, `Cert`, `Keystore` |
| `queries.sql.go` | Query methods on `*Queries` for cert/CA/intermediate operations |
| `keystore_queries.sql.go` | Query methods on `*Queries` for key storage operations |

## BUILD.bazel Pattern

```starlark
genrule(
    name = "sqlc_generate",
    srcs = [
        "queries.sql",
        "keystore_queries.sql",
        "migrations/001_init.sql",
    ],
    outs = [
        "sqlc_db.go",
        "sqlc_models.go",
        "queries.sql.go",
        "keystore_queries.sql.go",
    ],
    cmd = "... generates sqlc.yaml inline, runs sqlc generate ...",
    tools = ["@multitool//tools/sqlc"],
)

go_library(
    name = "store",
    srcs = [
        "db.go",
        ":sqlc_generate",  # includes all generated .go files
    ],
    embedsrcs = ["migrations/001_init.sql"],
    ...
)
```

Key points:
- Generated files are referenced via `:sqlc_generate` label, not by filename
- The genrule copies inputs to a temp directory, generates the yaml, runs sqlc, copies outputs back
- `EXECROOT=$$PWD` is saved before `cd` so output paths resolve correctly

## sqlc Query Syntax

Queries use sqlc's annotation comments:

```sql
-- name: GetCA :one
SELECT * FROM ca WHERE id = 1;

-- name: ListCerts :many
SELECT * FROM cert ORDER BY created_at DESC;

-- name: RevokeCert :execrows
UPDATE cert SET revoked_at = ? WHERE serial = ?;
```

| Annotation | Returns |
|---|---|
| `:one` | Single row struct + error |
| `:many` | Slice of structs + error |
| `:exec` | error only |
| `:execrows` | int64 (rows affected) + error |

## Adding New Queries

1. Add the SQL query to the appropriate `.sql` file with a sqlc annotation
2. If adding a new `.sql` file, add it to `srcs` and `outs` in the genrule, and update the inline yaml
3. Run `bazel build //internal/store:store` to regenerate
4. Use the new method via `store.Queries`

## Multitool Setup

sqlc is managed as a multitool binary in `.multitool.lock.json`. To update the version, change the URLs and sha256 checksums in the lock file.
