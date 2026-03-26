"""Bazel rule for sqlc Go code generation."""

load("@rules_go//go:def.bzl", "go_library")

def sqlc_go_library(name, queries, schema, package, importpath, visibility = None, deps = [], **kwargs):
    """Generates a go_library from sqlc SQL queries.

    Args:
        name: target name
        queries: list of .sql query files
        schema: list of schema SQL files (migrations)
        package: Go package name for generated code
        importpath: Go import path for the generated library
        visibility: Bazel visibility
        deps: additional Go dependencies
    """
    gen_name = name + "_sqlc_gen"

    # Output one .go file per query file, plus db.go and models.go
    query_outs = [q.rsplit("/", 1)[-1] + ".go" for q in queries]
    outs = ["sqlc_db.go", "sqlc_models.go"] + query_outs

    # Build the list of query file basenames for the yaml
    query_basenames = [q.rsplit("/", 1)[-1] for q in queries]
    queries_yaml = "[" + ", ".join(['\\"{}\\"'.format(q) for q in query_basenames]) + "]"

    native.genrule(
        name = gen_name,
        srcs = queries + schema,
        outs = outs,
        cmd = " && ".join([
            "EXECROOT=$$PWD",
            "SQLC=$$EXECROOT/$(execpath @multitool//tools/sqlc)",
            "WORK=$$(mktemp -d)",
            "mkdir -p $$WORK/migrations",
        ] + [
            "cp $(location {}) $$WORK/migrations/".format(s)
            for s in schema
        ] + [
            "cp $(location {}) $$WORK/".format(q)
            for q in queries
        ] + [
            # Generate sqlc.yaml inline
            "cat > $$WORK/sqlc.yaml << 'SQLCEOF'",
            'version: "2"',
            "sql:",
            '  - engine: "sqlite"',
            "    queries: {}".format(queries_yaml if len(queries) > 1 else query_basenames[0]),
            '    schema: "migrations/"',
            "    gen:",
            "      go:",
            '        package: "{}"'.format(package),
            '        out: "."',
            '        output_db_file_name: "sqlc_db.go"',
            '        output_models_file_name: "sqlc_models.go"',
            "SQLCEOF",
            "cd $$WORK",
            "$$SQLC generate",
        ] + [
            "cp $$WORK/{} $$EXECROOT/$(location {})".format(o, o)
            for o in outs
        ]),
        tools = ["@multitool//tools/sqlc"],
    )

    go_library(
        name = name,
        srcs = [":" + gen_name],
        importpath = importpath,
        visibility = visibility,
        deps = deps,
        **kwargs
    )
