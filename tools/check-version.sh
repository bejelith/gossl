#!/usr/bin/env bash
set -euo pipefail

# Validates that HEAD has a semver git tag. Run before release builds.
# Usage: tools/check-version.sh && bazel build --stamp //cmd/gossl:gossl_linux_amd64

GIT_TAG=$(git describe --tags --exact-match 2>/dev/null || echo "")

if [[ -z "${GIT_TAG}" ]]; then
  echo "ERROR: No git tag on current commit. Tag with a semver (e.g. git tag v0.1.0)" >&2
  exit 1
fi

if ! [[ "${GIT_TAG}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?$ ]]; then
  echo "ERROR: Tag '${GIT_TAG}' is not a valid semantic version (expected vMAJOR.MINOR.PATCH)" >&2
  exit 1
fi

echo "Version: ${GIT_TAG}"
