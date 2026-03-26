#!/usr/bin/env bash
set -euo pipefail

# Bazel workspace status command — outputs key-value pairs for stamping.
# When a semver tag exists on HEAD, it is used. Otherwise outputs "dev".
# Stamped builds (bazel build --stamp) will embed these values.
# Use tools/check-version.sh to enforce semver before release builds.

GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
GIT_TAG=$(git describe --tags --exact-match 2>/dev/null || echo "dev")

echo "STABLE_GIT_TAG ${GIT_TAG}"
echo "STABLE_GIT_COMMIT ${GIT_COMMIT}"
