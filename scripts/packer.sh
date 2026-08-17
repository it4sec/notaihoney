#!/usr/bin/env bash
set -euo pipefail

DATE=$(date +%Y-%m-%d)
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PACKAGE_DIR="${PROJECT_ROOT}/package"
ARCHIVE="${PACKAGE_DIR}/notaihoney-${DATE}.tar.gz"
INSTALLER_REL="scripts/installer_ubuntu24_runtime.sh"

if [[ ! -f "${PROJECT_ROOT}/${INSTALLER_REL}" ]]; then
    echo "Error: missing required installer: ${PROJECT_ROOT}/${INSTALLER_REL}" >&2
    exit 1
fi

mkdir -p "$PACKAGE_DIR"

tar -czf "$ARCHIVE" \
    -C "$PROJECT_ROOT" \
    --transform='s|^scripts/installer_ubuntu24_runtime\.sh$|installer_ubuntu24_runtime.sh|' \
    dist/notaihoney \
    config/honeypot.yaml \
    deploy/systemd/notaihoney.service \
    deploy/systemd/notaihoney-capture.service \
    deploy/nftables/base.nft \
    scripts

# Verify that the installer is stored only at the archive root.
if ! tar -tzf "$ARCHIVE" | grep -Fxq 'installer_ubuntu24_runtime.sh'; then
    echo "Error: archive does not contain installer_ubuntu24_runtime.sh at its root" >&2
    rm -f "$ARCHIVE"
    exit 1
fi

if tar -tzf "$ARCHIVE" | grep -Fxq 'scripts/installer_ubuntu24_runtime.sh'; then
    echo "Error: installer was also stored under scripts/" >&2
    rm -f "$ARCHIVE"
    exit 1
fi

echo "Created: $ARCHIVE"
