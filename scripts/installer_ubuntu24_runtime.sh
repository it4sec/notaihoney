#!/usr/bin/env bash
#
# notAIhoney runtime deployment installer
# Target: Ubuntu 24.04 LTS, amd64/x86_64, systemd host
#
# Run as root from a release-bundle directory containing:
#
#   installer_ubuntu24_runtime.sh
#   dist/notaihoney
#   config/honeypot.yaml
#   deploy/systemd/notaihoney.service
#   deploy/systemd/notaihoney-capture.service
#
# Optional release-bundle files:
#   notaihoney.sha256
#   server.crt
#   server.key
#
# By default the installer validates, starts, and enables both services without
# modifying the host firewall.
#
# Pass --apply-firewall to integrate validated listener ports into an existing,
# administrator-managed active UFW firewall. The installer never enables UFW
# and never manages native nftables persistence or service state.
#

set -Eeuo pipefail
IFS=$'\n\t'
umask 027

SERVE_USER="notaihoney"
SERVE_GROUP="notaihoney"
CAPTURE_USER="notaihoney-capture"
CAPTURE_GROUP="notaihoney-capture"
# Capture storage keeps its dedicated group, while the running capture service
# uses the serving group for controlled access to /run/notaihoney/capture.sock.
CAPTURE_RUNTIME_GROUP="$SERVE_GROUP"

INSTALL_ROOT="/etc/notaihoney"
TLS_DIR="${INSTALL_ROOT}/tls"

DATA_ROOT="/var/lib/notaihoney"
PCAP_DIR="${DATA_ROOT}/pcap"
JOURNAL_DIR="${DATA_ROOT}/journal"
EVENTS_DIR="${DATA_ROOT}/events"
INDEX_DIR="${DATA_ROOT}/index"

BINARY_DST="/usr/local/bin/notaihoney"
CONFIG_DST="${INSTALL_ROOT}/honeypot.yaml"

LISTENERS_JSON_DST="${INSTALL_ROOT}/listeners.json"

UFW_PROFILE_DIR="/etc/ufw/applications.d"
UFW_PROFILE_DST="${UFW_PROFILE_DIR}/notaihoney"
UFW_PROFILE_NAME="notAIhoney"
UFW_MANAGED_MARKER="# Managed by notAIhoney installer"

TLS_CERT_DST="${TLS_DIR}/server.crt"
TLS_KEY_DST="${TLS_DIR}/server.key"

SERVE_UNIT="notaihoney.service"
CAPTURE_UNIT="notaihoney-capture.service"

SERVE_UNIT_DST="/etc/systemd/system/${SERVE_UNIT}"
CAPTURE_UNIT_DST="/etc/systemd/system/${CAPTURE_UNIT}"

SERVE_DROPIN_DIR="/etc/systemd/system/${SERVE_UNIT}.d"
SERVE_DROPIN="${SERVE_DROPIN_DIR}/10-notaihoney-runtime.conf"

CAPTURE_DROPIN_DIR="/etc/systemd/system/${CAPTURE_UNIT}.d"
CAPTURE_DROPIN="${CAPTURE_DROPIN_DIR}/20-notaihoney-capture-capabilities.conf"

LIBEXEC_DIR="/usr/local/libexec"

READY_HELPER="${LIBEXEC_DIR}/notaihoney-wait-capture-ready"

APPLY_FIREWALL=0
PREPARE_ONLY=0
ACTIVATION_STARTED=0

TMP_FILES=()

log() {
    printf '[+] %s\n' "$*"
}

warn() {
    printf '[!] %s\n' "$*" >&2
}

fail_closed_services() {

    if (( ACTIVATION_STARTED )); then

        set +e

        systemctl stop "$SERVE_UNIT" >/dev/null 2>&1 || true
        systemctl stop "$CAPTURE_UNIT" >/dev/null 2>&1 || true

        systemctl disable "$SERVE_UNIT" >/dev/null 2>&1 || true
        systemctl disable "$CAPTURE_UNIT" >/dev/null 2>&1 || true

        set -e

    fi
}

die() {

    printf '[ERROR] %s\n' "$*" >&2

    fail_closed_services

    exit 1
}

cleanup() {

    local f

    for f in "${TMP_FILES[@]}"; do

        if [[ -n "$f" ]]; then
            rm -f -- "$f"
        fi

    done

    return 0
}

show_service_diagnostics() {

    local unit="$1"

    systemctl --no-pager --full status "$unit" >&2 2>/dev/null || true
    journalctl -u "$unit" -b --no-pager -n 80 >&2 2>/dev/null || true
}

on_error() {

    local rc=$?
    local line="${BASH_LINENO[0]:-unknown}"

    trap - ERR

    set +e

    fail_closed_services

    printf \
        '[ERROR] Installation failed at line %s (exit %s). Services are left stopped/disabled.\n' \
        "$line" \
        "$rc" \
        >&2

    exit "$rc"
}

trap cleanup EXIT
trap on_error ERR

usage() {

    cat <<'EOF_USAGE'
Usage: installer_ubuntu24_runtime.sh [--prepare-only] [--apply-firewall]

  --prepare-only
      Install and validate runtime artifacts but do not start or enable services.

  --apply-firewall
      Add/update only the notAIhoney UFW application profile and allow rule.
      Requires UFW to already be installed and active. Refuses operation when
      native nftables.service is active or enabled.

  -h, --help
      Show this help.
EOF_USAGE
}

while (($#)); do

    case "$1" in

        --prepare-only)
            PREPARE_ONLY=1
            ;;

        --apply-firewall)
            APPLY_FIREWALL=1
            ;;

        -h|--help)
            usage
            exit 0
            ;;

        *)
            die "Unknown argument: $1"
            ;;

    esac

    shift
done

[[ ${EUID} -eq 0 ]] || die "Run this installer as root."

[[ -d /run/systemd/system ]] || \
    die "A booted systemd host is required."

[[ "$(ps -p 1 -o comm= | tr -d '[:space:]')" == "systemd" ]] || \
    die "systemd must be PID 1."

# ---------------------------------------------------------------------------
# Release bundle
#
# IMPORTANT:
# The installer intentionally uses the CURRENT WORKING DIRECTORY.
#
# Run it from:
#
# .
# ├── installer_ubuntu24_runtime.sh
# ├── dist/notaihoney
# ├── config/honeypot.yaml
# ├── deploy/systemd/notaihoney.service
# └── deploy/systemd/notaihoney-capture.service
# ---------------------------------------------------------------------------

BUNDLE_DIR="$PWD"

BINARY_BUNDLE="${BUNDLE_DIR}/dist/notaihoney"

CONFIG_BUNDLE="${BUNDLE_DIR}/config/honeypot.yaml"

SERVE_UNIT_BUNDLE="${BUNDLE_DIR}/deploy/systemd/notaihoney.service"

CAPTURE_UNIT_BUNDLE="${BUNDLE_DIR}/deploy/systemd/notaihoney-capture.service"

# Optional files remain expected in the current bundle root.
SHA256_BUNDLE="${BUNDLE_DIR}/notaihoney.sha256"

TLS_CERT_BUNDLE="${BUNDLE_DIR}/server.crt"
TLS_KEY_BUNDLE="${BUNDLE_DIR}/server.key"

# ---------------------------------------------------------------------------
# 1. Validate platform and release bundle
# ---------------------------------------------------------------------------

log "Validating Ubuntu 24.04 amd64/x86_64 target"

[[ -r /etc/os-release ]] || \
    die "/etc/os-release is missing."

# shellcheck disable=SC1091
. /etc/os-release

[[ "${ID:-}" == "ubuntu" ]] || \
    die "Unsupported distribution: ${PRETTY_NAME:-unknown}. Ubuntu 24.04 LTS is required."

[[ "${VERSION_ID:-}" == "24.04" ]] || \
    die "Unsupported Ubuntu version: ${VERSION_ID:-unknown}. Ubuntu 24.04 LTS is required."

[[ "$(dpkg --print-architecture)" == "amd64" ]] || \
    die "Unsupported Debian architecture: $(dpkg --print-architecture). amd64 is required."

[[ "$(uname -m)" == "x86_64" ]] || \
    die "Unsupported kernel architecture: $(uname -m). x86_64 is required."

log "Validating runtime release bundle"

for path in \
    "$BINARY_BUNDLE" \
    "$CONFIG_BUNDLE" \
    "$SERVE_UNIT_BUNDLE" \
    "$CAPTURE_UNIT_BUNDLE"
do

    [[ -f "$path" ]] || \
        die "Required release-bundle file is missing: $path"

done

[[ -s "$BINARY_BUNDLE" ]] || \
    die "Release executable is empty: $BINARY_BUNDLE"

if [[ -e "$TLS_CERT_BUNDLE" || -e "$TLS_KEY_BUNDLE" ]]; then

    [[ -f "$TLS_CERT_BUNDLE" && -f "$TLS_KEY_BUNDLE" ]] || \
        die "TLS files must be supplied as a pair: server.crt and server.key."

fi


# ---------------------------------------------------------------------------
# 2. Install runtime packages only
# ---------------------------------------------------------------------------

log "Installing Ubuntu runtime packages"

export DEBIAN_FRONTEND=noninteractive

if command -v debconf-set-selections >/dev/null 2>&1; then

    printf '%s\n' \
        'wireshark-common wireshark-common/install-setuid boolean false' \
        | debconf-set-selections

fi

apt-get update

apt-get install -y --no-install-recommends \
    ca-certificates \
    debconf \
    file \
    iproute2 \
    jq \
    libcap2-bin \
    python3-minimal \
    socat \
    sqlite3 \
    wireshark-common

printf '%s\n' \
    'wireshark-common wireshark-common/install-setuid boolean false' \
    | debconf-set-selections

for cmd in \
    dumpcap \
    getcap \
    setcap \
    capsh \
    systemd-run \
    runuser \
    socat \
    jq \
    python3 \
    sha256sum \
    file \
    timeout \
    ss

do

    command -v "$cmd" >/dev/null 2>&1 || \
        die "Required runtime command is unavailable after package installation: $cmd"

done

# ---------------------------------------------------------------------------
# 3. Verify release executable compatibility and integrity
# ---------------------------------------------------------------------------

log "Verifying release executable compatibility"

FILE_INFO="$(file -b "$BINARY_BUNDLE")"

printf '    %s\n' "$FILE_INFO"

grep -q 'ELF 64-bit' <<<"$FILE_INFO" || \
    die "notaihoney is not a 64-bit ELF executable."

grep -q 'x86-64' <<<"$FILE_INFO" || \
    die "notaihoney is not an amd64/x86-64 executable."

LDD_OUTPUT="$(ldd "$BINARY_BUNDLE" 2>&1 || true)"

if grep -q 'not found' <<<"$LDD_OUTPUT"; then

    printf '%s\n' "$LDD_OUTPUT" >&2

    die "The release executable has unresolved shared-library dependencies."

fi

BUNDLE_SHA256="$(sha256sum "$BINARY_BUNDLE" | awk '{print $1}')"

if [[ -f "$SHA256_BUNDLE" ]]; then

    EXPECTED_SHA256="$(awk 'NF {print $1; exit}' "$SHA256_BUNDLE")"

    [[ "$EXPECTED_SHA256" =~ ^[[:xdigit:]]{64}$ ]] || \
        die "notaihoney.sha256 does not begin with a valid SHA-256 value."

    [[ "${EXPECTED_SHA256,,}" == "${BUNDLE_SHA256,,}" ]] || \
        die "Release executable SHA-256 does not match notaihoney.sha256."

fi

# ---------------------------------------------------------------------------
# 4. Stop existing deployment before changing installed artifacts
# ---------------------------------------------------------------------------

log "Stopping any existing notAIhoney services"

systemctl stop "$SERVE_UNIT" >/dev/null 2>&1 || true
systemctl stop "$CAPTURE_UNIT" >/dev/null 2>&1 || true

systemctl disable "$SERVE_UNIT" >/dev/null 2>&1 || true
systemctl disable "$CAPTURE_UNIT" >/dev/null 2>&1 || true

# ---------------------------------------------------------------------------
# 5. Create dedicated service identities
# ---------------------------------------------------------------------------

ensure_system_group() {

    local group="$1"
    local gid

    if getent group "$group" >/dev/null; then

        gid="$(getent group "$group" | cut -d: -f3)"

        (( gid < 1000 )) || \
            die "Existing group '$group' has non-system GID $gid; refusing to repurpose it."

    else

        log "Creating system group: $group"

        groupadd --system "$group"

    fi
}

ensure_system_user() {

    local user="$1"
    local group="$2"
    local uid

    ensure_system_group "$group"

    if id "$user" >/dev/null 2>&1; then

        uid="$(id -u "$user")"

        (( uid < 1000 )) || \
            die "Existing user '$user' has non-system UID $uid; refusing to repurpose it."

        [[ "$(id -gn "$user")" == "$group" ]] || \
            usermod --gid "$group" "$user"

        [[ "$(getent passwd "$user" | cut -d: -f6)" == "/nonexistent" ]] || \
            usermod --home /nonexistent "$user"

        [[ "$(getent passwd "$user" | cut -d: -f7)" == "/usr/sbin/nologin" ]] || \
            usermod --shell /usr/sbin/nologin "$user"

    else

        log "Creating system user: $user"

        useradd \
            --system \
            --gid "$group" \
            --home-dir /nonexistent \
            --no-create-home \
            --shell /usr/sbin/nologin \
            "$user"

    fi
}

ensure_system_user "$SERVE_USER" "$SERVE_GROUP"
ensure_system_user "$CAPTURE_USER" "$CAPTURE_GROUP"

# ---------------------------------------------------------------------------
# 6. Create deployment filesystem
# ---------------------------------------------------------------------------

log "Creating notAIhoney filesystem layout"

install -d \
    -o root \
    -g root \
    -m 0755 \
    "$INSTALL_ROOT"

install -d \
    -o root \
    -g "$SERVE_GROUP" \
    -m 0750 \
    "$TLS_DIR"

install -d \
    -o root \
    -g root \
    -m 0755 \
    "$DATA_ROOT"

install -d \
    -o "$CAPTURE_USER" \
    -g "$CAPTURE_GROUP" \
    -m 0750 \
    "$PCAP_DIR"

install -d \
    -o "$SERVE_USER" \
    -g "$SERVE_GROUP" \
    -m 0750 \
    "$JOURNAL_DIR"

install -d \
    -o "$SERVE_USER" \
    -g "$SERVE_GROUP" \
    -m 0750 \
    "$EVENTS_DIR"

install -d \
    -o "$SERVE_USER" \
    -g "$SERVE_GROUP" \
    -m 0750 \
    "$INDEX_DIR"

install -d \
    -o root \
    -g root \
    -m 0755 \
    "$LIBEXEC_DIR"

# ---------------------------------------------------------------------------
# 7. Install release artifacts and optional TLS material
# ---------------------------------------------------------------------------

log "Installing release artifacts"

install \
    -o root \
    -g root \
    -m 0755 \
    "$BINARY_BUNDLE" \
    "$BINARY_DST"

install \
    -o root \
    -g root \
    -m 0644 \
    "$CONFIG_BUNDLE" \
    "$CONFIG_DST"

install \
    -o root \
    -g root \
    -m 0644 \
    "$SERVE_UNIT_BUNDLE" \
    "$SERVE_UNIT_DST"

install \
    -o root \
    -g root \
    -m 0644 \
    "$CAPTURE_UNIT_BUNDLE" \
    "$CAPTURE_UNIT_DST"

INSTALLED_SHA256="$(sha256sum "$BINARY_DST" | awk '{print $1}')"

[[ "$BUNDLE_SHA256" == "$INSTALLED_SHA256" ]] || \
    die "Installed executable SHA-256 does not match the release bundle."

if [[ -f "$TLS_CERT_BUNDLE" && -f "$TLS_KEY_BUNDLE" ]]; then

    log "Installing TLS certificate and private key"

    install \
        -o root \
        -g "$SERVE_GROUP" \
        -m 0640 \
        "$TLS_CERT_BUNDLE" \
        "$TLS_CERT_DST"

    install \
        -o root \
        -g "$SERVE_GROUP" \
        -m 0640 \
        "$TLS_KEY_BUNDLE" \
        "$TLS_KEY_DST"

fi


# ---------------------------------------------------------------------------
# 8. Select capture interface and update the installed YAML
# ---------------------------------------------------------------------------

log "Detecting available network interfaces"

mapfile -t CAPTURE_INTERFACES < <(
    ip -o link show \
        | awk -F': ' '{print $2}' \
        | sed 's/@.*$//' \
        | awk '!seen[$0]++' \
        | awk '$0 != "lo"'
)

# Keep loopback available as an explicit last-resort choice.
if ip link show dev lo >/dev/null 2>&1; then
    CAPTURE_INTERFACES+=("lo")
fi

((${#CAPTURE_INTERFACES[@]} > 0)) || \
    die "No network interfaces were detected."

[[ -t 0 ]] || \
    die "Interactive terminal input is required to choose the capture interface."

printf '\nAvailable capture interfaces:\n'
for i in "${!CAPTURE_INTERFACES[@]}"; do
    printf '  %d) %s\n' "$((i + 1))" "${CAPTURE_INTERFACES[$i]}"
done
printf '\n'

while true; do
    read -r -p "Select capture interface [1-${#CAPTURE_INTERFACES[@]}]: " INTERFACE_CHOICE

    if [[ "$INTERFACE_CHOICE" =~ ^[0-9]+$ ]] \
        && (( INTERFACE_CHOICE >= 1 )) \
        && (( INTERFACE_CHOICE <= ${#CAPTURE_INTERFACES[@]} )); then
        CAPTURE_INTERFACE="${CAPTURE_INTERFACES[$((INTERFACE_CHOICE - 1))]}"
        break
    fi

    printf '[!] Invalid selection. Choose a number between 1 and %d.\n' \
        "${#CAPTURE_INTERFACES[@]}" >&2
done

ip link show dev "$CAPTURE_INTERFACE" >/dev/null 2>&1 || \
    die "Selected capture interface does not exist: $CAPTURE_INTERFACE"

log "Selected capture interface: $CAPTURE_INTERFACE"
log "Updating evidence.pcap.interface in $CONFIG_DST"

python3 - "$CONFIG_DST" "$CAPTURE_INTERFACE" <<'PY_UPDATE_INTERFACE'
import os
import re
import sys

path = sys.argv[1]
interface = sys.argv[2]

with open(path, "r", encoding="utf-8", newline="") as handle:
    lines = handle.readlines()

in_evidence = False
in_pcap = False
evidence_indent = None
pcap_indent = None
changed = False

for index, line in enumerate(lines):
    raw = line.rstrip("\r\n")
    stripped = raw.strip()

    if not stripped or stripped.startswith("#"):
        continue

    indent = len(raw) - len(raw.lstrip(" "))

    if not in_evidence:
        if re.fullmatch(r"evidence\s*:\s*(?:#.*)?", stripped):
            in_evidence = True
            evidence_indent = indent
        continue

    if indent <= evidence_indent:
        in_evidence = False
        in_pcap = False
        continue

    if not in_pcap:
        if re.fullmatch(r"pcap\s*:\s*(?:#.*)?", stripped):
            in_pcap = True
            pcap_indent = indent
        continue

    if indent <= pcap_indent:
        in_pcap = False
        continue

    match = re.match(r"^(\s*)interface\s*:\s*(.*?)(\s+#.*)?$", raw)
    if match:
        newline = "\r\n" if line.endswith("\r\n") else "\n" if line.endswith("\n") else ""
        comment = match.group(3) or ""
        lines[index] = f'{match.group(1)}interface: "{interface}"{comment}{newline}'
        changed = True
        break

if not changed:
    print(
        "[ERROR] Could not locate evidence.pcap.interface in the installed YAML.",
        file=sys.stderr,
    )
    sys.exit(1)

tmp = path + ".tmp"
with open(tmp, "w", encoding="utf-8", newline="") as handle:
    handle.writelines(lines)

os.chmod(tmp, os.stat(path).st_mode & 0o777)
os.replace(tmp, path)
PY_UPDATE_INTERFACE

chown root:root "$CONFIG_DST"
chmod 0644 "$CONFIG_DST"

# ---------------------------------------------------------------------------
# 9. Install readiness gate and enforce systemd identities/capture privileges
# ---------------------------------------------------------------------------

log "Installing capture-readiness gate"

cat >"$READY_HELPER" <<'EOF_READY'
#!/usr/bin/env bash

set -Eeuo pipefail
IFS=$'\n\t'

CONFIG="/etc/notaihoney/honeypot.yaml"
SOCKET="/run/notaihoney/capture.sock"

EXPECTED="$(sha256sum "$CONFIG" | awk '{print $1}')"

for _ in $(seq 1 30); do

    if [[ -S "$SOCKET" ]]; then

        RESPONSE="$(
            printf 'HEALTH\n' \
                | timeout 2 socat - "UNIX-CONNECT:${SOCKET}" 2>/dev/null \
                || true
        )"

        IFS=" " read -r STATE HASH SESSION REST <<<"$RESPONSE" || true

        if [[ "$STATE" == "READY" \
              && "$HASH" == "$EXPECTED" \
              && -n "${SESSION:-}" \
              && -z "${REST:-}" ]]; then

            exit 0

        fi

    fi

    sleep 1

done

printf \
    '[ERROR] capture service did not report READY with the installed configuration SHA-256.\n' \
    >&2

RUNTIME_DIR="$(dirname "$SOCKET")"

if [[ -d "$RUNTIME_DIR" ]]; then
    printf '[DIAG] runtime directory: ' >&2
    stat -c '%A %U:%G %n' "$RUNTIME_DIR" >&2 || true
else
    printf '[DIAG] runtime directory missing: %s\n' "$RUNTIME_DIR" >&2
fi

if [[ -S "$SOCKET" ]]; then
    printf '[DIAG] capture socket: ' >&2
    stat -c '%A %U:%G %n' "$SOCKET" >&2 || true
else
    printf '[DIAG] capture socket missing: %s\n' "$SOCKET" >&2
fi

if [[ -x "$RUNTIME_DIR" ]]; then
    printf '[DIAG] current identity can traverse runtime directory: yes\n' >&2
else
    printf '[DIAG] current identity can traverse runtime directory: no\n' >&2
fi

if [[ -S "$SOCKET" ]]; then
    FINAL_RESPONSE="$(
        printf 'HEALTH\n' \
            | timeout 2 socat - "UNIX-CONNECT:${SOCKET}" 2>&1 \
            || true
    )"
    printf '[DIAG] final HEALTH attempt: %s\n' "${FINAL_RESPONSE:-<no response>}" >&2
fi

exit 1
EOF_READY

chown root:root "$READY_HELPER"
chmod 0755 "$READY_HELPER"

log "Configuring systemd service identities and capture capabilities"

install -d \
    -o root \
    -g root \
    -m 0755 \
    "$SERVE_DROPIN_DIR"

cat >"$SERVE_DROPIN" <<EOF_SERVE
[Unit]
BindsTo=${CAPTURE_UNIT}
After=${CAPTURE_UNIT}

[Service]
User=${SERVE_USER}
Group=${SERVE_GROUP}
ExecStartPre=${READY_HELPER}
EOF_SERVE

chmod 0644 "$SERVE_DROPIN"

DUMPCAP="$(command -v dumpcap)"

[[ -f "$DUMPCAP" ]] || \
    die "dumpcap is not a regular file: $DUMPCAP"

[[ "$(stat -c '%u' "$DUMPCAP")" == "0" ]] || \
    die "Refusing to normalize dumpcap because it is not root-owned: $DUMPCAP"

# Capture privilege is supplied only by the capture service through systemd.

setcap -r "$DUMPCAP" 2>/dev/null || true

chown root:root "$DUMPCAP"
chmod 0755 "$DUMPCAP"

[[ -z "$(getcap "$DUMPCAP" 2>/dev/null)" ]] || \
    die "Unexpected filesystem capabilities remain on $DUMPCAP."

[[ "$(stat -c '%a' "$DUMPCAP")" == "755" ]] || \
    die "Unexpected dumpcap mode after normalization."

install -d \
    -o root \
    -g root \
    -m 0755 \
    "$CAPTURE_DROPIN_DIR"

cat >"$CAPTURE_DROPIN" <<EOF_CAPTURE
[Service]
User=${CAPTURE_USER}
Group=${CAPTURE_RUNTIME_GROUP}

NoNewPrivileges=true

CapabilityBoundingSet=
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN

AmbientCapabilities=
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN

ReadWritePaths=${PCAP_DIR}
EOF_CAPTURE

chmod 0644 "$CAPTURE_DROPIN"

for unit_file in \
    "$SERVE_UNIT_DST" \
    "$CAPTURE_UNIT_DST"

do

    if grep -Eq \
        '^[[:space:]]*ExecStart=[[:space:]]*[-@:!]*\+' \
        "$unit_file"
    then

        die "$(basename "$unit_file") contains a privileged '+' ExecStart prefix."

    fi

done

systemctl daemon-reload

# ---------------------------------------------------------------------------
# 10. Validate effective systemd security properties
# ---------------------------------------------------------------------------

log "Validating systemd units and effective properties"

systemd-analyze verify \
    "$SERVE_UNIT" \
    "$CAPTURE_UNIT"

SERVE_EFFECTIVE_USER="$(
    systemctl show "$SERVE_UNIT" -p User --value
)"

SERVE_EFFECTIVE_GROUP="$(
    systemctl show "$SERVE_UNIT" -p Group --value
)"

SERVE_AMBIENT="$(
    systemctl show "$SERVE_UNIT" -p AmbientCapabilities --value
)"

SERVE_PRIVATE_NETWORK="$(
    systemctl show "$SERVE_UNIT" -p PrivateNetwork --value 2>/dev/null || true
)"

[[ "$SERVE_EFFECTIVE_USER" == "$SERVE_USER" ]] || \
    die "$SERVE_UNIT effective User= is '$SERVE_EFFECTIVE_USER'."

[[ "$SERVE_EFFECTIVE_GROUP" == "$SERVE_GROUP" ]] || \
    die "$SERVE_UNIT effective Group= is '$SERVE_EFFECTIVE_GROUP'."

[[ "$SERVE_PRIVATE_NETWORK" != "yes" ]] || \
    die "$SERVE_UNIT has PrivateNetwork=yes, which prevents host-facing listeners."

if grep -Eqi \
    '(^|[[:space:]])cap_net_(raw|admin)($|[[:space:]])' \
    <<<"$SERVE_AMBIENT"
then

    die "$SERVE_UNIT unexpectedly receives packet-capture ambient capabilities: $SERVE_AMBIENT"

fi

CAPTURE_EFFECTIVE_USER="$(
    systemctl show "$CAPTURE_UNIT" -p User --value
)"

CAPTURE_EFFECTIVE_GROUP="$(
    systemctl show "$CAPTURE_UNIT" -p Group --value
)"

CAPTURE_NNP="$(
    systemctl show "$CAPTURE_UNIT" -p NoNewPrivileges --value
)"

CAPTURE_BOUNDING="$(
    systemctl show "$CAPTURE_UNIT" -p CapabilityBoundingSet --value
)"

CAPTURE_AMBIENT="$(
    systemctl show "$CAPTURE_UNIT" -p AmbientCapabilities --value
)"

CAPTURE_PRIVATE_NETWORK="$(
    systemctl show "$CAPTURE_UNIT" -p PrivateNetwork --value 2>/dev/null || true
)"

CAPTURE_RESTRICT_AF="$(
    systemctl show "$CAPTURE_UNIT" -p RestrictAddressFamilies --value 2>/dev/null || true
)"

CAPTURE_RUNTIME_DIRECTORY="$(
    systemctl show "$CAPTURE_UNIT" -p RuntimeDirectory --value 2>/dev/null || true
)"

CAPTURE_RUNTIME_MODE="$(
    systemctl show "$CAPTURE_UNIT" -p RuntimeDirectoryMode --value 2>/dev/null || true
)"

[[ "$CAPTURE_EFFECTIVE_USER" == "$CAPTURE_USER" ]] || \
    die "$CAPTURE_UNIT effective User= is '$CAPTURE_EFFECTIVE_USER'."

[[ "$CAPTURE_EFFECTIVE_GROUP" == "$CAPTURE_RUNTIME_GROUP" ]] || \
    die "$CAPTURE_UNIT effective Group= is '$CAPTURE_EFFECTIVE_GROUP'; expected '$CAPTURE_RUNTIME_GROUP'."

[[ "$CAPTURE_NNP" == "yes" ]] || \
    die "$CAPTURE_UNIT effective NoNewPrivileges= is '$CAPTURE_NNP'."

[[ "$CAPTURE_PRIVATE_NETWORK" != "yes" ]] || \
    die "$CAPTURE_UNIT has PrivateNetwork=yes, which conflicts with host packet capture."

grep -qw 'notaihoney' <<<"$CAPTURE_RUNTIME_DIRECTORY" || \
    die "$CAPTURE_UNIT RuntimeDirectory does not include notaihoney: $CAPTURE_RUNTIME_DIRECTORY"

[[ -n "$CAPTURE_RUNTIME_MODE" ]] || \
    die "$CAPTURE_UNIT RuntimeDirectoryMode is not defined."

CAPTURE_BOUNDING_LC="${CAPTURE_BOUNDING,,}"
CAPTURE_AMBIENT_LC="${CAPTURE_AMBIENT,,}"

for cap in \
    cap_net_raw \
    cap_net_admin

do

    grep -qw "$cap" <<<"$CAPTURE_BOUNDING_LC" || \
        die "$CAPTURE_UNIT CapabilityBoundingSet is missing $cap."

    grep -qw "$cap" <<<"$CAPTURE_AMBIENT_LC" || \
        die "$CAPTURE_UNIT AmbientCapabilities is missing $cap."

done

[[ "$(wc -w <<<"$CAPTURE_BOUNDING")" -eq 2 ]] || \
    die "$CAPTURE_UNIT has unexpected capabilities in CapabilityBoundingSet: $CAPTURE_BOUNDING"

[[ "$(wc -w <<<"$CAPTURE_AMBIENT")" -eq 2 ]] || \
    die "$CAPTURE_UNIT has unexpected capabilities in AmbientCapabilities: $CAPTURE_AMBIENT"

if [[ -n "$CAPTURE_RESTRICT_AF" ]]; then

    grep -qw 'AF_PACKET' <<<"$CAPTURE_RESTRICT_AF" || \
        die "$CAPTURE_UNIT RestrictAddressFamilies is missing AF_PACKET."

    grep -qw 'AF_UNIX' <<<"$CAPTURE_RESTRICT_AF" || \
        die "$CAPTURE_UNIT RestrictAddressFamilies is missing AF_UNIX for capture.sock."

    grep -qw 'AF_NETLINK' <<<"$CAPTURE_RESTRICT_AF" || \
        die "$CAPTURE_UNIT RestrictAddressFamilies is missing AF_NETLINK for Go network-interface lookup."

fi

# ---------------------------------------------------------------------------
# 11. Verify filesystem separation and TLS access
# ---------------------------------------------------------------------------

log "Validating service-account filesystem permissions"

runuser -u "$SERVE_USER" -- \
    test -r "$CONFIG_DST" || \
    die "$SERVE_USER cannot read $CONFIG_DST."

runuser -u "$CAPTURE_USER" -- \
    test -r "$CONFIG_DST" || \
    die "$CAPTURE_USER cannot read $CONFIG_DST."

runuser -u "$SERVE_USER" -- \
    test -w "$JOURNAL_DIR" || \
    die "$SERVE_USER cannot write $JOURNAL_DIR."

runuser -u "$SERVE_USER" -- \
    test -w "$EVENTS_DIR" || \
    die "$SERVE_USER cannot write $EVENTS_DIR."

runuser -u "$SERVE_USER" -- \
    test -w "$INDEX_DIR" || \
    die "$SERVE_USER cannot write $INDEX_DIR."

runuser -u "$CAPTURE_USER" -- \
    test -w "$PCAP_DIR" || \
    die "$CAPTURE_USER cannot write $PCAP_DIR."

if runuser -u "$CAPTURE_USER" -- test -r "$TLS_DIR"; then

    die "$CAPTURE_USER unexpectedly has read access to $TLS_DIR."

fi

if [[ -f "$TLS_KEY_DST" || -f "$TLS_CERT_DST" ]]; then

    [[ -f "$TLS_KEY_DST" && -f "$TLS_CERT_DST" ]] || \
        die "Installed TLS material is incomplete."

    runuser -u "$SERVE_USER" -- \
        test -r "$TLS_CERT_DST" || \
        die "$SERVE_USER cannot read $TLS_CERT_DST."

    runuser -u "$SERVE_USER" -- \
        test -r "$TLS_KEY_DST" || \
        die "$SERVE_USER cannot read $TLS_KEY_DST."

    if runuser -u "$CAPTURE_USER" -- test -r "$TLS_KEY_DST"; then

        die "$CAPTURE_USER unexpectedly has read access to $TLS_KEY_DST."

    fi

fi

# ---------------------------------------------------------------------------
# 12. Isolated capture privilege smoke test
# ---------------------------------------------------------------------------

log "Running isolated non-root dumpcap capability smoke test"

SMOKE_FILE="${PCAP_DIR}/.dumpcap-permission-smoke-test.pcapng"
SMOKE_UNIT="notaihoney-dumpcap-smoke-${$}.service"

rm -f -- "$SMOKE_FILE"

if ! systemd-run \
    --quiet \
    --wait \
    --pipe \
    --collect \
    --unit="$SMOKE_UNIT" \
    -p "User=$CAPTURE_USER" \
    -p "Group=$CAPTURE_GROUP" \
    -p "NoNewPrivileges=yes" \
    -p "CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN" \
    -p "AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN" \
    "$DUMPCAP" \
        -q \
        -i lo \
        -a duration:1 \
        -w "$SMOKE_FILE"

then

    rm -f -- "$SMOKE_FILE"

    die "Non-root dumpcap capability smoke test failed."

fi

[[ -s "$SMOKE_FILE" ]] || \
    die "dumpcap smoke test did not create a PCAPNG file."

[[ "$(stat -c '%U:%G' "$SMOKE_FILE")" == "${CAPTURE_USER}:${CAPTURE_GROUP}" ]] || \
    die "dumpcap smoke-test file has unexpected ownership."

rm -f -- "$SMOKE_FILE"

# ---------------------------------------------------------------------------
# 13. Start capture and require READY before operational validation
# ---------------------------------------------------------------------------

log "Starting capture service before operational configuration validation"

ACTIVATION_STARTED=1

systemctl start "$CAPTURE_UNIT" || {
    show_service_diagnostics "$CAPTURE_UNIT"
    die "Failed to start $CAPTURE_UNIT."
}

systemctl is-active --quiet "$CAPTURE_UNIT" || {
    show_service_diagnostics "$CAPTURE_UNIT"
    die "$CAPTURE_UNIT is not active."
}

log "Waiting for capture READY with the installed configuration hash"

if ! runuser \
    -u "$SERVE_USER" \
    -- "$READY_HELPER"
then
    show_service_diagnostics "$CAPTURE_UNIT"
    die "Capture readiness validation failed."
fi

# ---------------------------------------------------------------------------
# 14. Validate application configuration and listener export
# ---------------------------------------------------------------------------

log "Running notAIhoney operational configuration validation"

CHECK_OUTPUT="$(mktemp)"
LISTENER_OUTPUT="$(mktemp)"

TMP_FILES+=(
    "$CHECK_OUTPUT"
    "$LISTENER_OUTPUT"
)

if ! "$BINARY_DST" \
    check \
    --config "$CONFIG_DST" \
    | tee "$CHECK_OUTPUT"

then

    die "notAIhoney operational configuration validation failed."

fi

log "Exporting validated listener definition"

if ! "$BINARY_DST" \
    check \
    --config "$CONFIG_DST" \
    --emit-listeners=json \
    >"$LISTENER_OUTPUT"

then

    die "Listener export failed."

fi

jq -e . "$LISTENER_OUTPUT" >/dev/null || \
    die "Listener export is not valid JSON."

CONFIG_SHA256="$(
    sha256sum "$CONFIG_DST" | awk '{print $1}'
)"

if ! jq -e \
    --arg expected "$CONFIG_SHA256" \
    '.. | strings | select(. == $expected)' \
    "$LISTENER_OUTPUT" \
    >/dev/null

then

    die "Listener export does not contain the installed configuration SHA-256 ($CONFIG_SHA256)."

fi

install \
    -o root \
    -g root \
    -m 0644 \
    "$LISTENER_OUTPUT" \
    "$LISTENERS_JSON_DST"

# ---------------------------------------------------------------------------
# 15. Safe UFW integration when explicitly requested
# ---------------------------------------------------------------------------

FIREWALL_MANAGER="none"
FIREWALL_APPLIED=0
FIREWALL_MODIFIED=0
LISTENER_PORTS_CSV=""

ufw_notaihoney_rule_present() {

    LC_ALL=C ufw status 2>/dev/null \
        | awk -v app="$UFW_PROFILE_NAME" '
            $1 == app && $2 == "ALLOW" { found=1 }
            END { exit(found ? 0 : 1) }
        '
}

validate_generated_ufw_profile() {

    local profile="$1"
    local expected_ports="$2"
    local ports_line

    [[ -f "$profile" ]] || return 1
    [[ "$(sed -n '1p' "$profile")" == "$UFW_MANAGED_MARKER" ]] || return 1
    grep -Fqx "[$UFW_PROFILE_NAME]" "$profile" || return 1
    grep -Fqx 'title=notAIhoney listeners' "$profile" || return 1
    grep -Fqx 'description=Generated from validated notAIhoney listener configuration' "$profile" || return 1

    [[ "$(grep -c '^ports=' "$profile")" -eq 1 ]] || return 1
    ports_line="$(sed -n 's/^ports=//p' "$profile")"
    [[ "$ports_line" == "$expected_ports" ]] || return 1
    [[ "$ports_line" =~ ^[1-9][0-9]{0,4}/tcp(\|[1-9][0-9]{0,4}/tcp)*$ ]] || return 1
}

if (( APPLY_FIREWALL )); then

    FIREWALL_MANAGER="UFW"

    log "Running UFW firewall preflight"

    command -v ufw >/dev/null 2>&1 || \
        die "--apply-firewall refused: UFW is not installed."

    UFW_STATUS="$(LC_ALL=C ufw status 2>&1)" || \
        die "--apply-firewall refused: unable to query UFW status."

    grep -q '^Status: active$' <<<"$UFW_STATUS" || \
        die "--apply-firewall refused: UFW is not active."

    if systemctl is-active --quiet nftables.service 2>/dev/null \
        || systemctl is-enabled --quiet nftables.service 2>/dev/null
    then
        die "--apply-firewall refused: native nftables management is active or enabled."
    fi

    [[ -d "$UFW_PROFILE_DIR" ]] || \
        die "--apply-firewall refused: UFW application-profile directory is missing: $UFW_PROFILE_DIR"

    log "Validating listener export for port-only UFW integration"

    jq -e '
        type == "object"
        and has("listeners")
        and (.listeners | type == "array")
        and (.listeners | length > 0)
        and all(.listeners[];
            type == "object"
            and has("address")
            and has("port")
            and has("protocol")
            and (.address | type == "string")
            and (.port | type == "number")
            and (.port == (.port | floor))
            and (.port >= 1 and .port <= 65535)
            and (.protocol | type == "string")
            and (.protocol == "http" or .protocol == "https")
        )
    ' "$LISTENERS_JSON_DST" >/dev/null || \
        die "--apply-firewall refused: listener export is malformed or contains unsupported listener data."

    if ! jq -e 'all(.listeners[]; .address == "0.0.0.0")' \
        "$LISTENERS_JSON_DST" >/dev/null
    then
        die "--apply-firewall refused: port-only UFW integration supports only listeners bound to 0.0.0.0; refusing to broaden address-scoped exposure."
    fi

    mapfile -t LISTENER_PORTS < <(
        jq -r '[.listeners[].port | floor] | sort | unique | .[]' \
            "$LISTENERS_JSON_DST"
    )

    ((${#LISTENER_PORTS[@]} > 0)) || \
        die "--apply-firewall refused: listener export contains no TCP ports."

    LISTENER_PORTS_CSV="$(IFS=,; printf '%s' "${LISTENER_PORTS[*]}")"

    UFW_PORTS_SPEC=""
    for port in "${LISTENER_PORTS[@]}"; do
        if [[ -n "$UFW_PORTS_SPEC" ]]; then
            UFW_PORTS_SPEC+="|"
        fi
        UFW_PORTS_SPEC+="${port}/tcp"
    done

    PROFILE_TMP="$(mktemp)"
    TMP_FILES+=("$PROFILE_TMP")

    cat >"$PROFILE_TMP" <<EOF_UFW_PROFILE
$UFW_MANAGED_MARKER
[$UFW_PROFILE_NAME]
title=notAIhoney listeners
description=Generated from validated notAIhoney listener configuration
ports=$UFW_PORTS_SPEC
EOF_UFW_PROFILE

    validate_generated_ufw_profile "$PROFILE_TMP" "$UFW_PORTS_SPEC" || \
        die "Generated notAIhoney UFW application profile failed validation."

    UFW_PROFILE_EXISTED=0
    UFW_RULE_EXISTED=0
    UFW_PROFILE_CHANGED=1
    UFW_PROFILE_BACKUP=""

    if [[ -e "$UFW_PROFILE_DST" ]]; then

        [[ -f "$UFW_PROFILE_DST" ]] || \
            die "Existing UFW profile '$UFW_PROFILE_DST' is not a regular file; refusing to overwrite it."

        [[ "$(sed -n '1p' "$UFW_PROFILE_DST")" == "$UFW_MANAGED_MARKER" ]] || \
            die "Existing UFW profile 'notaihoney' is not installer-managed. Refusing to overwrite it."

        UFW_PROFILE_EXISTED=1
        UFW_PROFILE_BACKUP="$(mktemp)"
        TMP_FILES+=("$UFW_PROFILE_BACKUP")
        cp -a -- "$UFW_PROFILE_DST" "$UFW_PROFILE_BACKUP"

        if cmp -s "$PROFILE_TMP" "$UFW_PROFILE_DST"; then
            UFW_PROFILE_CHANGED=0
        fi

    fi

    if ufw_notaihoney_rule_present; then
        UFW_RULE_EXISTED=1
    elif (( ! UFW_PROFILE_EXISTED )); then
        # A named rule without an installer-managed profile has ambiguous
        # ownership. Refuse rather than guessing or reconstructing it.
        if LC_ALL=C ufw status 2>/dev/null | grep -Eq '^notAIhoney([[:space:]]|$)'; then
            die "Existing notAIhoney UFW rule is not backed by an installer-managed profile; refusing to modify it."
        fi
    fi

    rollback_notaihoney_ufw() {

        set +e

        # Always attempt removal before restoring the previous profile. If the
        # just-added rule exists but status parsing failed, this still removes
        # only the notAIhoney application rule. Failure is harmless here when
        # no such rule exists.
        ufw delete allow "$UFW_PROFILE_NAME" >/dev/null 2>&1 || true

        if (( UFW_PROFILE_EXISTED )); then
            install -o root -g root -m 0644 \
                "$UFW_PROFILE_BACKUP" "$UFW_PROFILE_DST" >/dev/null 2>&1 || true
        else
            rm -f -- "$UFW_PROFILE_DST"
        fi

        if (( UFW_RULE_EXISTED )); then
            ufw allow "$UFW_PROFILE_NAME" >/dev/null 2>&1 || true
        fi

        set -e
    }

    install_ufw_profile_atomically() {

        local stage

        stage="$(mktemp "${UFW_PROFILE_DIR}/.notaihoney.XXXXXX")" || return 1
        TMP_FILES+=("$stage")

        install -o root -g root -m 0644 "$PROFILE_TMP" "$stage" || return 1
        mv -fT -- "$stage" "$UFW_PROFILE_DST" || return 1

        [[ "$(stat -c '%U:%G' "$UFW_PROFILE_DST")" == "root:root" ]] || return 1
        [[ "$(stat -c '%a' "$UFW_PROFILE_DST")" == "644" ]] || return 1
    }

    if (( ! UFW_PROFILE_CHANGED && UFW_RULE_EXISTED )); then

        log "notAIhoney UFW rule already matches validated listeners"
        FIREWALL_APPLIED=1

    else

        log "Updating only the notAIhoney UFW application profile and allow rule"

        if (( UFW_RULE_EXISTED )); then
            if ! ufw delete allow "$UFW_PROFILE_NAME" >/dev/null; then
                rollback_notaihoney_ufw
                die "Failed to remove the existing notAIhoney UFW allow rule."
            fi
        fi

        if (( UFW_PROFILE_CHANGED )); then
            if ! install_ufw_profile_atomically; then
                rollback_notaihoney_ufw
                die "Failed to atomically install the notAIhoney UFW application profile."
            fi

            if ! validate_generated_ufw_profile "$UFW_PROFILE_DST" "$UFW_PORTS_SPEC"; then
                rollback_notaihoney_ufw
                die "Installed notAIhoney UFW profile failed validation."
            fi

            if ! LC_ALL=C ufw app info "$UFW_PROFILE_NAME" >/dev/null 2>&1; then
                rollback_notaihoney_ufw
                die "UFW did not accept the installed notAIhoney application profile."
            fi
        fi

        if ! ufw allow "$UFW_PROFILE_NAME" >/dev/null; then
            rollback_notaihoney_ufw
            die "Failed to add the notAIhoney UFW allow rule."
        fi

        if ! ufw_notaihoney_rule_present; then
            rollback_notaihoney_ufw
            die "notAIhoney UFW allow rule was not present after application."
        fi

        FIREWALL_APPLIED=1
        FIREWALL_MODIFIED=1

    fi

fi

# ---------------------------------------------------------------------------
# 16. Start serving after validated capture/configuration
# ---------------------------------------------------------------------------

if (( PREPARE_ONLY )); then

    log "Stopping temporary capture service used for operational validation"
    systemctl stop "$CAPTURE_UNIT" >/dev/null 2>&1 || true
    systemctl disable "$CAPTURE_UNIT" >/dev/null 2>&1 || true
    systemctl disable "$SERVE_UNIT" >/dev/null 2>&1 || true
    ACTIVATION_STARTED=0

    log "Runtime installation and validation completed in prepare-only mode."

    printf '    binary:              %s\n' "$BINARY_DST"
    printf '    binary SHA-256:      %s\n' "$INSTALLED_SHA256"
    printf '    configuration:       %s\n' "$CONFIG_DST"
    printf '    config SHA-256:      %s\n' "$CONFIG_SHA256"
    printf '    listener export:     %s\n' "$LISTENERS_JSON_DST"

    printf '    firewall requested:  %s\n' "$([[ $APPLY_FIREWALL -eq 1 ]] && echo yes || echo no)"
    printf '    firewall modified:   %s\n' "$([[ $FIREWALL_MODIFIED -eq 1 ]] && echo yes || echo no)"

    if (( APPLY_FIREWALL )); then
        printf '    firewall manager:    %s\n' "$FIREWALL_MANAGER"
        printf '    firewall profile:    %s\n' "$UFW_PROFILE_DST"
        printf '    firewall applied:    %s\n' "$([[ $FIREWALL_APPLIED -eq 1 ]] && echo yes || echo no)"
        printf '    listener ports:      %s\n' "$LISTENER_PORTS_CSV"
    fi

    printf \
        'Services remain stopped and disabled because --prepare-only was requested.\n'

    exit 0

fi

log "Starting serving service"

systemctl start "$SERVE_UNIT" || {

    show_service_diagnostics "$SERVE_UNIT"

    die "Failed to start $SERVE_UNIT."

}

sleep 1

systemctl is-active --quiet "$SERVE_UNIT" || {

    show_service_diagnostics "$SERVE_UNIT"

    die "$SERVE_UNIT is not active."

}

systemctl is-active --quiet "$CAPTURE_UNIT" || {

    show_service_diagnostics "$CAPTURE_UNIT"

    die "$CAPTURE_UNIT stopped after serving startup."

}

log "Enabling services for boot"

systemctl enable \
    "$CAPTURE_UNIT" \
    "$SERVE_UNIT"

systemctl is-enabled --quiet "$CAPTURE_UNIT" || \
    die "$CAPTURE_UNIT was not enabled."

systemctl is-enabled --quiet "$SERVE_UNIT" || \
    die "$SERVE_UNIT was not enabled."

# Re-query readiness after serving startup to catch immediate capture loss.

runuser \
    -u "$SERVE_USER" \
    -- "$READY_HELPER" || {

        show_service_diagnostics "$CAPTURE_UNIT"

        die "Capture READY state was lost after serving startup."

    }

ACTIVATION_STARTED=0

printf '\n'

log "notAIhoney runtime deployment completed successfully."

printf '    binary:              %s\n' "$BINARY_DST"
printf '    binary SHA-256:      %s\n' "$INSTALLED_SHA256"

printf '    configuration:       %s\n' "$CONFIG_DST"
printf '    config SHA-256:      %s\n' "$CONFIG_SHA256"

printf '    listener export:     %s\n' "$LISTENERS_JSON_DST"

printf \
    '    serving identity:    %s:%s\n' \
    "$SERVE_USER" \
    "$SERVE_GROUP"

printf \
    '    capture runtime:     %s:%s\n' \
    "$CAPTURE_USER" \
    "$CAPTURE_RUNTIME_GROUP"

printf \
    '    PCAP ownership:      %s:%s\n' \
    "$CAPTURE_USER" \
    "$CAPTURE_GROUP"

printf '    capture service:     active + enabled\n'
printf '    serving service:     active + enabled\n'

printf '    firewall requested:  %s\n' "$([[ $APPLY_FIREWALL -eq 1 ]] && echo yes || echo no)"
printf '    firewall modified:   %s\n' "$([[ $FIREWALL_MODIFIED -eq 1 ]] && echo yes || echo no)"

if (( APPLY_FIREWALL )); then
    printf '    firewall manager:    %s\n' "$FIREWALL_MANAGER"
    printf '    firewall profile:    %s\n' "$UFW_PROFILE_DST"
    printf '    firewall applied:    %s\n' "$([[ $FIREWALL_APPLIED -eq 1 ]] && echo yes || echo no)"
    printf '    listener ports:      %s\n' "$LISTENER_PORTS_CSV"
fi

printf '\n'

ss -ltnp || true

if (( ! APPLY_FIREWALL )); then

    warn \
        "The server is running and the installer did not modify the host firewall. Use --apply-firewall only when administrator-managed UFW is already installed and active."

fi
