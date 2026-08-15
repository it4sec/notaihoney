#!/usr/bin/env bash
#
# prepare_notaihoney_storage.sh
#
# Prepare the local filesystem paths required by notAIhoney.
#
# Intended for DEVELOPMENT / LOCAL TESTING.
#
# Creates:
#   /var/lib/notaihoney/
#   /var/lib/notaihoney/pcap
#   /var/lib/notaihoney/journal
#   /var/lib/notaihoney/events
#   /var/lib/notaihoney/index
#
# When executed through sudo, ownership is assigned to the user who invoked
# sudo so that notaihoney can be run manually as that user.
#
# This script DOES NOT:
#   - modify honeypot.yaml
#   - select or change the capture interface
#   - configure dumpcap permissions
#   - create production service accounts
#

set -euo pipefail

BASE_DIR="/var/lib/notaihoney"

REQUIRED_DIRS=(
    "${BASE_DIR}/pcap"
    "${BASE_DIR}/journal"
    "${BASE_DIR}/events"
    "${BASE_DIR}/index"
)

# honeypot.yaml requirement:
# min_free_bytes: 5368709120
MIN_FREE_BYTES=5368709120


# ---------------------------------------------------------------------------
# Root check
# ---------------------------------------------------------------------------

if [[ "${EUID}" -ne 0 ]]; then
    echo "ERROR: This script must be run as root."
    echo
    echo "Run:"
    echo "  sudo $0"
    exit 1
fi


# ---------------------------------------------------------------------------
# Determine development owner
# ---------------------------------------------------------------------------

if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
    DEV_USER="${SUDO_USER}"
else
    DEV_USER=""
fi


echo "=========================================="
echo " notAIhoney storage preparation"
echo "=========================================="
echo


# ---------------------------------------------------------------------------
# Create directory hierarchy
# ---------------------------------------------------------------------------

echo "[1/4] Creating storage directories..."

for directory in "${REQUIRED_DIRS[@]}"; do
    if [[ -d "${directory}" ]]; then
        echo "  EXISTS  ${directory}"
    else
        mkdir -p "${directory}"
        echo "  CREATED ${directory}"
    fi
done

echo


# ---------------------------------------------------------------------------
# Development ownership
# ---------------------------------------------------------------------------

echo "[2/4] Configuring ownership..."

if [[ -n "${DEV_USER}" ]]; then
    DEV_GROUP="$(id -gn "${DEV_USER}")"

    chown -R "${DEV_USER}:${DEV_GROUP}" "${BASE_DIR}"

    echo "  Owner: ${DEV_USER}:${DEV_GROUP}"
    echo
    echo "  NOTE: This ownership model is appropriate for local development."
    echo "  Production deployment should use the dedicated notaihoney and"
    echo "  notaihoney-capture service ownership model."
else
    echo "  WARNING: Could not determine a non-root invoking user."
    echo "  Ownership has been left unchanged."
    echo
    echo "  If this is a development machine, run this script using:"
    echo "    sudo $0"
    echo "  from your normal user account."
fi

echo


# ---------------------------------------------------------------------------
# Verify directories
# ---------------------------------------------------------------------------

echo "[3/4] Verifying required paths..."

FAILED=0

for directory in "${REQUIRED_DIRS[@]}"; do
    if [[ ! -d "${directory}" ]]; then
        echo "  FAIL ${directory}"
        FAILED=1
        continue
    fi

    if [[ -n "${DEV_USER}" ]]; then
        if sudo -u "${DEV_USER}" test -w "${directory}"; then
            echo "  PASS ${directory} (writable by ${DEV_USER})"
        else
            echo "  FAIL ${directory} (not writable by ${DEV_USER})"
            FAILED=1
        fi
    else
        echo "  PASS ${directory} (exists)"
    fi
done

if [[ "${FAILED}" -ne 0 ]]; then
    echo
    echo "ERROR: One or more required storage paths failed validation."
    exit 1
fi

echo


# ---------------------------------------------------------------------------
# Check filesystem free space
# ---------------------------------------------------------------------------

echo "[4/4] Checking available filesystem space..."

AVAILABLE_BYTES="$(
    df --output=avail -B1 "${BASE_DIR}" \
        | tail -n 1 \
        | tr -d '[:space:]'
)"

if ! [[ "${AVAILABLE_BYTES}" =~ ^[0-9]+$ ]]; then
    echo "ERROR: Unable to determine available filesystem space."
    exit 1
fi

AVAILABLE_GIB="$(awk -v bytes="${AVAILABLE_BYTES}" \
    'BEGIN { printf "%.2f", bytes / 1073741824 }')"

MIN_GIB="$(awk -v bytes="${MIN_FREE_BYTES}" \
    'BEGIN { printf "%.2f", bytes / 1073741824 }')"

echo "  Available: ${AVAILABLE_GIB} GiB"
echo "  Required:  ${MIN_GIB} GiB"

if (( AVAILABLE_BYTES < MIN_FREE_BYTES )); then
    echo
    echo "WARNING: The directories are configured correctly, but the filesystem"
    echo "does not satisfy the honeypot.yaml min_free_bytes requirement."
    echo
    echo "Configured minimum:"
    echo "  ${MIN_FREE_BYTES} bytes (${MIN_GIB} GiB)"
    echo
    echo "The notAIhoney operational check may therefore still fail."
else
    echo "  PASS: Free-space requirement satisfied."
fi


echo
echo "=========================================="
echo " Storage preparation complete"
echo "=========================================="
echo
echo "Configured paths:"
for directory in "${REQUIRED_DIRS[@]}"; do
    echo "  ${directory}"
done

echo
echo "Next inspect the host network interfaces:"
echo
echo "  ip -brief link"
echo
echo "Then ensure:"
echo
echo "  evidence:"
echo "    pcap:"
echo "      interface: \"<actual-interface>\""
echo
echo "matches an interface that exists on this host."
echo
echo "Finally rerun:"
echo
echo '  "$NOTAIHONEY_BINARY" check --config config/honeypot.yaml'
echo