#!/usr/bin/env bash
set -euo pipefail

REPO="bejelith/gossl"
INSTALL_DIR="/usr/local/bin"

# Detect OS and architecture
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "${ARCH}" in
  x86_64)  ARCH="amd64" ;;
  aarch64) ARCH="arm64" ;;
  arm64)   ARCH="arm64" ;;
  *)
    echo "Unsupported architecture: ${ARCH}" >&2
    exit 1
    ;;
esac

case "${OS}" in
  linux|darwin) ;;
  *)
    echo "Unsupported OS: ${OS}" >&2
    exit 1
    ;;
esac

# Get latest release tag
echo "Fetching latest release..."
TAG=$(curl -sL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | cut -d'"' -f4)

if [ -z "${TAG}" ]; then
  echo "Failed to fetch latest release" >&2
  exit 1
fi

BINARY="gossl_${TAG}_${OS}_${ARCH}"
URL="https://github.com/${REPO}/releases/download/${TAG}/${BINARY}"

echo "Downloading gossl ${TAG} for ${OS}/${ARCH}..."
TMP=$(mktemp)
trap "rm -f ${TMP}" EXIT

curl -sL -o "${TMP}" "${URL}"

if [ ! -s "${TMP}" ]; then
  echo "Download failed: ${URL}" >&2
  exit 1
fi

chmod +x "${TMP}"

echo "Installing to ${INSTALL_DIR}/gossl..."
if [ -w "${INSTALL_DIR}" ]; then
  mv "${TMP}" "${INSTALL_DIR}/gossl"
else
  sudo mv "${TMP}" "${INSTALL_DIR}/gossl"
fi

echo "gossl ${TAG} installed successfully"
gossl --version
