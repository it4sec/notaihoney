#!/usr/bin/env bash
set -euo pipefail

SOURCE_DIR="/var/lib/notaihoney"

# Resolve the destination home directory.
# When invoked via sudo, store evidence under the original sudo user's home.
if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
    OUTPUT_USER="${SUDO_USER}"
    OUTPUT_HOME="$(getent passwd "${SUDO_USER}" | cut -d: -f6)"
else
    OUTPUT_USER="$(id -un)"
    OUTPUT_HOME="${HOME}"
fi

if [[ -z "${OUTPUT_HOME}" || ! -d "${OUTPUT_HOME}" ]]; then
    echo "[!] Unable to determine a valid home directory for ${OUTPUT_USER}" >&2
    exit 1
fi

OUTPUT_DIR="${OUTPUT_HOME}/honeypot_data"
TIMESTAMP="$(date '+%Y%m%d_%H%M%S')"
ARCHIVE_NAME="notAIhoney_${TIMESTAMP}.gz"
ARCHIVE_PATH="${OUTPUT_DIR}/${ARCHIVE_NAME}"

echo "[+] notAIhoney evidence collection"
echo "[+] Source:      ${SOURCE_DIR}"
echo "[+] Destination: ${ARCHIVE_PATH}"

if [[ ! -d "${SOURCE_DIR}" ]]; then
    echo "[!] Evidence directory does not exist: ${SOURCE_DIR}" >&2
    exit 1
fi

mkdir -p "${OUTPUT_DIR}"

echo "[+] Collecting current evidence state..."

# Archive the complete notAIhoney evidence hierarchy as it exists now.
# The running services are not stopped, paused, restarted, or modified.
tar \
    --create \
    --gzip \
    --file="${ARCHIVE_PATH}" \
    --directory="/var/lib" \
    "notaihoney"

echo "[+] Verifying archive..."

if ! tar -tzf "${ARCHIVE_PATH}" >/dev/null; then
    echo "[!] Archive verification failed: ${ARCHIVE_PATH}" >&2
    rm -f "${ARCHIVE_PATH}"
    exit 1
fi

# Return the generated evidence package to the original sudo user.
if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
    OUTPUT_GROUP="$(id -gn "${SUDO_USER}")"
    chown "${SUDO_USER}:${OUTPUT_GROUP}" "${OUTPUT_DIR}" "${ARCHIVE_PATH}"
fi

echo "[+] Evidence collection completed successfully."
echo
echo "Archive:"
echo "  ${ARCHIVE_PATH}"
echo
echo "Size:"
du -h "${ARCHIVE_PATH}" | awk '{print "  " $1}'
echo
echo "SHA-256:"
sha256sum "${ARCHIVE_PATH}"