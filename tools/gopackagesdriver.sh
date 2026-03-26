#!/usr/bin/env bash
set -euo pipefail

exec bazel run -- @rules_go//go/tools/gopackagesdriver "${@}"
