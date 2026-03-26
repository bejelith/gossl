#!/usr/bin/env bash
set -euo pipefail

# Run bazel coverage and aggregate LCOV results into a single report.
# Usage: tools/coverage.sh [bazel test targets...]
# Default: //...

TARGETS="${*:-//...}"
COMBINED="/tmp/gossl-coverage-combined.dat"

echo "Running coverage for ${TARGETS}..."

# When invoked via bazel run, cd to the workspace root
if [[ -n "${BUILD_WORKSPACE_DIRECTORY:-}" ]]; then
  cd "${BUILD_WORKSPACE_DIRECTORY}"
fi

# Use a separate output base to avoid lock contention when invoked via bazel run
COVERAGE_OUTPUT_BASE="$(mktemp -d)"
trap "rm -rf ${COVERAGE_OUTPUT_BASE}" EXIT
bazel --output_base="${COVERAGE_OUTPUT_BASE}" coverage "${TARGETS}" 2>&1 | grep -E "(PASSED|FAILED|coverage report)"

# Bazel writes a combined report when --combined_report=lcov is set
REPORT="$(bazel --output_base="${COVERAGE_OUTPUT_BASE}" info output_path)/_coverage/_coverage_report.dat"

if [[ ! -f "${REPORT}" ]]; then
  echo "ERROR: No coverage report found at ${REPORT}"
  exit 1
fi

cp "${REPORT}" "${COMBINED}"

# Filter out test files and parse LCOV to compute coverage
awk '
  /^SF:/ {
    file = $0
    sub(/^SF:/, "", file)
    is_test = (file ~ /_test\.go$/)
  }
  /^DA:/ && !is_test {
    split($0, a, ":")
    split(a[2], b, ",")
    total++
    if (b[2] > 0) hit++
  }
  END {
    if (total > 0) {
      pct = (hit / total) * 100
      printf "\n=== Coverage Summary ===\n"
      printf "Lines:   %d / %d (%.1f%%)\n", hit, total, pct
      if (pct < 80) {
        printf "WARNING: Below 80%% target\n"
        exit 1
      }
    } else {
      print "No coverage data found"
      exit 1
    }
  }
' "${COMBINED}"

echo "LCOV report: ${COMBINED}"
