---
name: code-review
description: Use when reviewing code quality, security, coverage, style compliance, or dependency health — run before merging or on demand
---

# Code Review

Run a comprehensive code review across 5 dimensions, each in a parallel agent. Reviews the diff between the current branch and master. If already on master, reviews the entire codebase.

## Scope Detection

Determine review scope BEFORE dispatching agents:

```bash
CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
if [ "$CURRENT_BRANCH" = "master" ] || [ "$CURRENT_BRANCH" = "main" ]; then
  SCOPE="full"
  FILES="all files in the repository"
else
  SCOPE="diff"
  FILES=$(git diff --name-only master...HEAD)
fi
```

If `SCOPE=diff` and no files changed, report "No reviewable changes" and stop.

Announce the scope to the user before dispatching:
- **Diff mode**: "Reviewing N changed files against master..."
- **Full mode**: "On master — reviewing entire codebase..."

## Dispatch

Launch ALL 5 agents in parallel using the Agent tool. Pass each agent:
- The `SCOPE` (full or diff)
- The list of changed files (if diff mode)
- The full text of the relevant agent instructions below
- The project's CLAUDE.md content (for style agent)

## Agent 1: Test Coverage

**Goal**: Identify packages/modules below 80% unit test coverage and flag untested code paths.

**Instructions for agent**:
- Read CLAUDE.md for project-specific test and build commands.
- Run the project's test coverage command (e.g., `bazel coverage //...`, `go test -cover`, `pytest --cov`, `npm test -- --coverage` — whatever the project uses).
- Parse coverage output to extract per-package/module percentages.
- If in diff mode, focus on packages containing changed files.
- For each package below 80%, list the uncovered functions/methods.
- Flag any changed functions that have zero test coverage.
- **Go-specific**: Parse Bazel coverage profiles or `go tool cover` output. Check that table-driven tests cover all branches. Identify exported functions without any test exercising them.

**Output format**:
```
## Coverage Report

Overall: X% (target: 80%)

| Package/Module | Coverage | Status |
|----------------|----------|--------|
| internal/store | 72% | BELOW TARGET |
| internal/ca | 85% | OK |

### Uncovered Code
- `internal/store/db.go:45` — `OpenDB()` error path not tested
```

## Agent 2: Style Compliance

**Goal**: Review code against the project's style rules defined in CLAUDE.md.

**Instructions for agent**:
- Read `/Users/scaruso/dev/gossl/CLAUDE.md` for the full style guide and coding conventions.
- If diff mode, review only changed files. If full mode, review all source files.
- Check every rule listed in the style sections of CLAUDE.md.
- Run any project-specific formatting/lint commands mentioned in CLAUDE.md.
- Report each violation with file, line, rule violated, and suggested fix.
- **Go-specific checks** (from CLAUDE.md and Effective Go / CodeReviewComments):
  - Run `bazel run //tools/format:format.check` for formatting.
  - MixedCaps naming, no underscores. Initialisms in consistent case (`URL`, `ID`, not `Url`, `Id`).
  - Package names: short, lowercase, single-word. No stutter (`ring.Buffer` not `ring.RingBuffer`).
  - Error strings: lowercase, no trailing punctuation.
  - Always check errors. Never discard with `_` unless documented why.
  - Early returns for error handling — happy path at minimal indentation.
  - Interfaces: small, defined at consumer, not producer. Don't predefine for mocking.
  - `context.Context` as first parameter. Never store in structs.
  - Pointer receivers for mutation/large structs/consistency. Never mix receiver types on a type.
  - Receiver names: 1-2 letters, consistent, never `this`/`self`.
  - Prefer synchronous APIs. Let callers manage concurrency.
  - Document goroutine lifetimes. Don't leak goroutines.
  - Table-driven tests. Failure messages: `Foo(%q) = %d, want %d`.
  - `crypto/rand` for secrets, never `math/rand`.
  - `var s []T` for nil slices, not `s := []T{}` (unless JSON requires `[]`).
  - All exported names have doc comments — complete sentences starting with the name.

**Output format**:
```
## Style Review

### Violations
- **WARN** `internal/store/db.go:12` — Receiver name `store` should be 1-2 letters (e.g., `s`). [receiver-names]
- **WARN** `internal/ca/store.go:8` — Missing doc comment on exported type `CertStore`. [doc-comments]

### Passed Checks
- Formatting: OK
- Naming conventions: OK (except above)
```

## Agent 3: Code Security

**Goal**: Find security vulnerabilities in source code and configuration files.

**Instructions for agent**:
- If diff mode, review changed files. If full mode, review all source and config files.
- Scan for OWASP Top 10 issues across all languages and file types:
  - Injection flaws (SQL injection, command injection, template injection)
  - Path traversal (unsanitized file paths)
  - Insecure cryptography (weak algorithms, hardcoded keys)
  - Insecure TLS/SSL configuration (skip verify, weak cipher suites, outdated protocols)
  - Race conditions (shared state without synchronization)
  - Unsafe memory operations (buffer overflows, unsafe pointer usage)
  - Unbounded reads/allocations (DoS vectors)
  - Improper input validation at system boundaries
  - Broken access control patterns
  - Security misconfiguration in build/deploy configs
- Check build system configs (Bazel, Makefiles, Dockerfiles) for insecure settings.
- Rate each finding: **CRITICAL**, **WARNING**, or **INFO**.
- **Go-specific**:
  - `math/rand` used where `crypto/rand` is needed for secrets.
  - `sql.Query` with `fmt.Sprintf` instead of parameterized queries.
  - `os/exec.Command` with unsanitized user input.
  - `net/http` without timeouts on server or client.
  - `tls.Config` with `InsecureSkipVerify: true`.
  - `unsafe` package usage without justification.
  - Missing `defer rows.Close()` / `defer resp.Body.Close()`.
  - Race conditions: goroutines sharing state without mutexes or channels.
  - Minimum cryptographic key lengths: RSA keys must be >= 2048 bits (4096 preferred), ECDSA must use P-256 or stronger. Flag any code that accepts or generates keys below these thresholds.
  - Minimum TLS version: must enforce TLS 1.3 (`tls.VersionTLS13`). Flag TLS configs that allow TLS 1.2 or lower.
  - Weak hash algorithms: flag use of MD5, SHA-1 for signatures or integrity (acceptable for non-security checksums only).
  - Certificate validation: flag code that doesn't validate certificate chains, accepts expired certs, or skips revocation checks.

**Output format**:
```
## Security Review

### Findings
- **CRITICAL** `internal/store/db.go:34` — SQL query uses fmt.Sprintf with user input. Use parameterized queries.
- **WARNING** `cmd/server/main.go:22` — TLS MinVersion not set, defaults may allow TLS 1.0.

### No Issues Found
- Command injection: OK
- Path traversal: OK
```

## Agent 4: Dependency Security

**Goal**: Identify known vulnerabilities and obsolete packages in direct and transitive dependencies.

**Instructions for agent**:
- Read all dependency files: `go.mod`, `go.sum`, `package.json`, `package-lock.json`, `requirements.txt`, `Pipfile.lock`, `Cargo.toml`, `MODULE.bazel` — whatever exists in the project.
- Use language-specific vulnerability scanners if available:
  - Go: `bazel run //tools:govulncheck -- ./...`
  - Node: `npm audit`
  - Python: `pip-audit` or `safety check`
  - Rust: `cargo audit`
- If scanners are not available, manually review dependencies:
  - Search the web for known CVEs against each direct dependency and its version.
  - Flag any dependency more than 2 major versions behind latest.
  - Flag dependencies with known security advisories.
- Check for deprecated or unmaintained packages (archived repos, no commits in 2+ years).
- In diff mode, focus on newly added or changed dependencies.
- **Go-specific**:
  - Run `govulncheck ./...` for Go vulnerability database checks.
  - Review `go.sum` for unexpected dependency changes.
  - Check `golang.org/x/*` packages are on recent versions (these get frequent security patches).
  - Flag `replace` directives in `go.mod` that point to forks or local paths.
  - Check Bazel `MODULE.bazel` for `bazel_dep` versions and `go_deps` module extensions.

**Output format**:
```
## Dependency Security

### Vulnerabilities
- **CRITICAL** `golang.org/x/crypto v0.1.0` — CVE-2023-XXXXX: buffer overflow in ssh package. Upgrade to v0.17.0+.

### Outdated
- **WARNING** `modernc.org/sqlite v1.47.0` — latest is v1.50.0

### Status
- Direct dependencies: N checked, X issues
- Transitive dependencies: N checked, X issues
```

## Agent 5: Secret Leaks

**Goal**: Detect hardcoded secrets, tokens, API keys, and credentials across all files.

**Instructions for agent**:
- If diff mode, scan changed files. If full mode, scan entire repo.
- Scan ALL file types — source code, config, scripts, CI pipelines, docs:
  - Hardcoded passwords, tokens, API keys, private keys, certificates
  - Connection strings with embedded credentials
  - Base64-encoded secrets (high-entropy strings in assignments)
  - Sensitive data written to logs (passwords, tokens, keys in logging calls)
- Scan configuration and CI files explicitly:
  - `.pre-commit-config.yaml`, `.github/workflows/*.yml`, `.gitlab-ci.yml`
  - `Dockerfile`, `docker-compose.yml`
  - `MODULE.bazel`, `BUILD.bazel`, `.bazelrc`
  - Any shell scripts in `tools/`, `scripts/`, `ci/`
- Check for files that should be gitignored but aren't:
  - `.env`, `.env.*`, `credentials.*`, `*.pem`, `*.key`, `*.p12`, `*.jks`
  - `serviceaccount*.json`, `*-credentials.json`
- Check `.gitignore` for adequate coverage of secret file patterns.
- Rate each finding: **CRITICAL** (likely real secret), **WARNING** (possible secret or bad practice), **INFO** (suggestion).
- **Go-specific**:
  - Check for secrets in `const` or `var` blocks at package level.
  - Check `init()` functions for hardcoded credentials.
  - Check test files for real credentials used as test fixtures (vs obviously fake ones).
  - Look for secrets passed via `os.Setenv` in code rather than environment config.

**Output format**:
```
## Secret Leak Review

### Findings
- **CRITICAL** `config/db.go:15` — Hardcoded database password: `password := "admin123"`
- **WARNING** `cmd/main.go:8` — Token value logged at info level: `log.Printf("token: %s", token)`

### Gitignore Check
- `.env`: covered
- `*.pem`: NOT covered — add to .gitignore

### No Issues Found
- CI pipelines: OK
- Test fixtures: OK
```

## Consolidation

After all 5 agents complete, present a unified report:

```
# Code Review Report

## Summary
| Area | Critical | Warning | Info |
|------|----------|---------|------|
| Coverage | 0 | 2 | 1 |
| Style | 0 | 3 | 0 |
| Code Security | 1 | 0 | 2 |
| Dependencies | 0 | 1 | 0 |
| Secrets | 0 | 0 | 0 |
| **Total** | **1** | **6** | **3** |

## Critical Issues (fix before merge)
[list all CRITICAL findings across all agents]

## Warnings (should fix)
[list all WARNING findings]

## Info (consider)
[list all INFO findings]
```

Sort findings by severity, then by agent order. If there are critical issues, end with: "**Block merge** — N critical issues require fixing."
