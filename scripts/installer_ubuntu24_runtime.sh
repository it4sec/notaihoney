#!/usr/bin/env bash
#
# notAIhoney runtime deployment installer
# Target: Ubuntu 24.04 LTS, amd64/x86_64, systemd host
#
# Run as root from a release-bundle directory containing:
#   installer_ubuntu24_runtime.sh
#   notaihoney
#   honeypot.yaml
#   notaihoney.service
#   notaihoney-capture.service
#   base.nft
#
# Optional release-bundle files:
#   notaihoney.sha256        expected SHA-256 for the release executable
#   server.crt               TLS certificate; must be paired with server.key
#   server.key               TLS private key; must be paired with server.crt
#   listeners-to-nft         runtime deployment helper: JSON on stdin, nft fragment on stdout
#
# By default the installer validates, starts, and enables both services. It does
# not apply nftables automatically because host-management access and recovery
# cannot be proven by an installer. Pass --apply-firewall to explicitly load the
# validated /etc/notaihoney/base.nft ruleset after listener generation succeeds.
#

set -Eeuo pipefail
IFS=$'\n\t'
umask 027

SERVE_USER="notaihoney"
SERVE_GROUP="notaihoney"
CAPTURE_USER="notaihoney-capture"
CAPTURE_GROUP="notaihoney-capture"

INSTALL_ROOT="/etc/notaihoney"
TLS_DIR="${INSTALL_ROOT}/tls"
DATA_ROOT="/var/lib/notaihoney"
PCAP_DIR="${DATA_ROOT}/pcap"
JOURNAL_DIR="${DATA_ROOT}/journal"
EVENTS_DIR="${DATA_ROOT}/events"
INDEX_DIR="${DATA_ROOT}/index"

BINARY_DST="/usr/local/bin/notaihoney"
CONFIG_DST="${INSTALL_ROOT}/honeypot.yaml"
BASE_NFT_DST="${INSTALL_ROOT}/base.nft"
LISTENERS_JSON_DST="${INSTALL_ROOT}/listeners.json"
GENERATED_NFT_DST="${INSTALL_ROOT}/generated-listeners.nft"
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
NFT_GENERATOR_DST="${LIBEXEC_DIR}/notaihoney-listeners-to-nft"

APPLY_FIREWALL=0
PREPARE_ONLY=0
ACTIVATION_STARTED=0
TMP_FILES=()

log()  { printf '[+] %s\n' "$*"; }
warn() { printf '[!] %s\n' "$*" >&2; }

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
    printf '[ERROR] Installation failed at line %s (exit %s). Services are left stopped/disabled.\n' "$line" "$rc" >&2
    exit "$rc"
}

trap cleanup EXIT
trap on_error ERR

usage() {
    cat <<'EOF_USAGE'
Usage: installer_ubuntu24_runtime.sh [--prepare-only] [--apply-firewall]

  --prepare-only     Install and validate runtime artifacts but do not start or enable services.
  --apply-firewall   Explicitly load /etc/notaihoney/base.nft after deterministic listener
                     generation and nftables syntax validation. This can change remote access.
  -h, --help         Show this help.
EOF_USAGE
}

while (($#)); do
    case "$1" in
        --prepare-only) PREPARE_ONLY=1 ;;
        --apply-firewall) APPLY_FIREWALL=1 ;;
        -h|--help) usage; exit 0 ;;
        *) die "Unknown argument: $1" ;;
    esac
    shift
done

[[ ${EUID} -eq 0 ]] || die "Run this installer as root."
[[ -d /run/systemd/system ]] || die "A booted systemd host is required."
[[ "$(ps -p 1 -o comm= | tr -d '[:space:]')" == "systemd" ]] || die "systemd must be PID 1."

BUNDLE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

BINARY_BUNDLE="${BUNDLE_DIR}/notaihoney"
CONFIG_BUNDLE="${BUNDLE_DIR}/honeypot.yaml"
SERVE_UNIT_BUNDLE="${BUNDLE_DIR}/${SERVE_UNIT}"
CAPTURE_UNIT_BUNDLE="${BUNDLE_DIR}/${CAPTURE_UNIT}"
BASE_NFT_BUNDLE="${BUNDLE_DIR}/base.nft"
SHA256_BUNDLE="${BUNDLE_DIR}/notaihoney.sha256"
TLS_CERT_BUNDLE="${BUNDLE_DIR}/server.crt"
TLS_KEY_BUNDLE="${BUNDLE_DIR}/server.key"
NFT_GENERATOR_BUNDLE="${BUNDLE_DIR}/listeners-to-nft"

# ---------------------------------------------------------------------------
# 1. Validate platform and release bundle
# ---------------------------------------------------------------------------

log "Validating Ubuntu 24.04 amd64/x86_64 target"
[[ -r /etc/os-release ]] || die "/etc/os-release is missing."
# shellcheck disable=SC1091
. /etc/os-release

[[ "${ID:-}" == "ubuntu" ]] || die "Unsupported distribution: ${PRETTY_NAME:-unknown}. Ubuntu 24.04 LTS is required."
[[ "${VERSION_ID:-}" == "24.04" ]] || die "Unsupported Ubuntu version: ${VERSION_ID:-unknown}. Ubuntu 24.04 LTS is required."
[[ "$(dpkg --print-architecture)" == "amd64" ]] || die "Unsupported Debian architecture: $(dpkg --print-architecture). amd64 is required."
[[ "$(uname -m)" == "x86_64" ]] || die "Unsupported kernel architecture: $(uname -m). x86_64 is required."

log "Validating runtime release bundle"
for path in \
    "$BINARY_BUNDLE" \
    "$CONFIG_BUNDLE" \
    "$SERVE_UNIT_BUNDLE" \
    "$CAPTURE_UNIT_BUNDLE" \
    "$BASE_NFT_BUNDLE"; do
    [[ -f "$path" ]] || die "Required release-bundle file is missing: $path"
done
[[ -s "$BINARY_BUNDLE" ]] || die "Release executable is empty: $BINARY_BUNDLE"

if [[ -e "$TLS_CERT_BUNDLE" || -e "$TLS_KEY_BUNDLE" ]]; then
    [[ -f "$TLS_CERT_BUNDLE" && -f "$TLS_KEY_BUNDLE" ]] || die "TLS files must be supplied as a pair: server.crt and server.key."
fi

if [[ -e "$NFT_GENERATOR_BUNDLE" && ! -f "$NFT_GENERATOR_BUNDLE" ]]; then
    die "listeners-to-nft exists but is not a regular file."
fi

# ---------------------------------------------------------------------------
# 2. Install runtime packages only
# ---------------------------------------------------------------------------

log "Installing Ubuntu runtime packages"
export DEBIAN_FRONTEND=noninteractive

if command -v debconf-set-selections >/dev/null 2>&1; then
    printf '%s\n' 'wireshark-common wireshark-common/install-setuid boolean false' | debconf-set-selections
fi

apt-get update
apt-get install -y --no-install-recommends \
    ca-certificates \
    debconf \
    file \
    iproute2 \
    jq \
    libcap2-bin \
    nftables \
    socat \
    sqlite3 \
    wireshark-common

printf '%s\n' 'wireshark-common wireshark-common/install-setuid boolean false' | debconf-set-selections

for cmd in dumpcap getcap setcap capsh systemd-run runuser socat jq nft sha256sum file timeout ss; do
    command -v "$cmd" >/dev/null 2>&1 || die "Required runtime command is unavailable after package installation: $cmd"
done

# ---------------------------------------------------------------------------
# 3. Verify release executable compatibility and integrity
# ---------------------------------------------------------------------------

log "Verifying release executable compatibility"
FILE_INFO="$(file -b "$BINARY_BUNDLE")"
printf '    %s\n' "$FILE_INFO"
grep -q 'ELF 64-bit' <<<"$FILE_INFO" || die "notaihoney is not a 64-bit ELF executable."
grep -q 'x86-64' <<<"$FILE_INFO" || die "notaihoney is not an amd64/x86-64 executable."

LDD_OUTPUT="$(ldd "$BINARY_BUNDLE" 2>&1 || true)"
if grep -q 'not found' <<<"$LDD_OUTPUT"; then
    printf '%s\n' "$LDD_OUTPUT" >&2
    die "The release executable has unresolved shared-library dependencies."
fi

BUNDLE_SHA256="$(sha256sum "$BINARY_BUNDLE" | awk '{print $1}')"
if [[ -f "$SHA256_BUNDLE" ]]; then
    EXPECTED_SHA256="$(awk 'NF {print $1; exit}' "$SHA256_BUNDLE")"
    [[ "$EXPECTED_SHA256" =~ ^[[:xdigit:]]{64}$ ]] || die "notaihoney.sha256 does not begin with a valid SHA-256 value."
    [[ "${EXPECTED_SHA256,,}" == "${BUNDLE_SHA256,,}" ]] || die "Release executable SHA-256 does not match notaihoney.sha256."
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
        (( gid < 1000 )) || die "Existing group '$group' has non-system GID $gid; refusing to repurpose it."
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
        (( uid < 1000 )) || die "Existing user '$user' has non-system UID $uid; refusing to repurpose it."
        [[ "$(id -gn "$user")" == "$group" ]] || usermod --gid "$group" "$user"
        [[ "$(getent passwd "$user" | cut -d: -f6)" == "/nonexistent" ]] || usermod --home /nonexistent "$user"
        [[ "$(getent passwd "$user" | cut -d: -f7)" == "/usr/sbin/nologin" ]] || usermod --shell /usr/sbin/nologin "$user"
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
install -d -o root -g root -m 0755 "$INSTALL_ROOT"
install -d -o root -g "$SERVE_GROUP" -m 0750 "$TLS_DIR"

install -d -o root -g root -m 0755 "$DATA_ROOT"
install -d -o "$CAPTURE_USER" -g "$CAPTURE_GROUP" -m 0750 "$PCAP_DIR"
install -d -o "$SERVE_USER" -g "$SERVE_GROUP" -m 0750 "$JOURNAL_DIR"
install -d -o "$SERVE_USER" -g "$SERVE_GROUP" -m 0750 "$EVENTS_DIR"
install -d -o "$SERVE_USER" -g "$SERVE_GROUP" -m 0750 "$INDEX_DIR"
install -d -o root -g root -m 0755 "$LIBEXEC_DIR"

# ---------------------------------------------------------------------------
# 7. Install release artifacts and optional TLS material
# ---------------------------------------------------------------------------

log "Installing release artifacts"
install -o root -g root -m 0755 "$BINARY_BUNDLE" "$BINARY_DST"
install -o root -g root -m 0644 "$CONFIG_BUNDLE" "$CONFIG_DST"
install -o root -g root -m 0644 "$BASE_NFT_BUNDLE" "$BASE_NFT_DST"
install -o root -g root -m 0644 "$SERVE_UNIT_BUNDLE" "$SERVE_UNIT_DST"
install -o root -g root -m 0644 "$CAPTURE_UNIT_BUNDLE" "$CAPTURE_UNIT_DST"

INSTALLED_SHA256="$(sha256sum "$BINARY_DST" | awk '{print $1}')"
[[ "$BUNDLE_SHA256" == "$INSTALLED_SHA256" ]] || die "Installed executable SHA-256 does not match the release bundle."

if [[ -f "$TLS_CERT_BUNDLE" && -f "$TLS_KEY_BUNDLE" ]]; then
    log "Installing TLS certificate and private key"
    install -o root -g "$SERVE_GROUP" -m 0640 "$TLS_CERT_BUNDLE" "$TLS_CERT_DST"
    install -o root -g "$SERVE_GROUP" -m 0640 "$TLS_KEY_BUNDLE" "$TLS_KEY_DST"
fi

if [[ -f "$NFT_GENERATOR_BUNDLE" ]]; then
    install -o root -g root -m 0755 "$NFT_GENERATOR_BUNDLE" "$NFT_GENERATOR_DST"
else
    rm -f -- "$NFT_GENERATOR_DST"
fi

# ---------------------------------------------------------------------------
# 8. Install readiness gate and enforce systemd identities/capture privileges
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
        RESPONSE="$(printf 'HEALTH\n' | timeout 2 socat - "UNIX-CONNECT:${SOCKET}" 2>/dev/null || true)"
        read -r STATE HASH SESSION REST <<<"$RESPONSE" || true
        if [[ "$STATE" == "READY" && "$HASH" == "$EXPECTED" && -n "${SESSION:-}" && -z "${REST:-}" ]]; then
            exit 0
        fi
    fi
    sleep 1
done

printf '[ERROR] capture service did not report READY with the installed configuration SHA-256.\n' >&2
exit 1
EOF_READY
chown root:root "$READY_HELPER"
chmod 0755 "$READY_HELPER"

log "Configuring systemd service identities and capture capabilities"
install -d -o root -g root -m 0755 "$SERVE_DROPIN_DIR"
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
[[ -f "$DUMPCAP" ]] || die "dumpcap is not a regular file: $DUMPCAP"
[[ "$(stat -c '%u' "$DUMPCAP")" == "0" ]] || die "Refusing to normalize dumpcap because it is not root-owned: $DUMPCAP"

# Capture privilege is supplied only by the capture service through systemd.
setcap -r "$DUMPCAP" 2>/dev/null || true
chown root:root "$DUMPCAP"
chmod 0755 "$DUMPCAP"
[[ -z "$(getcap "$DUMPCAP" 2>/dev/null)" ]] || die "Unexpected filesystem capabilities remain on $DUMPCAP."
[[ "$(stat -c '%a' "$DUMPCAP")" == "755" ]] || die "Unexpected dumpcap mode after normalization."

install -d -o root -g root -m 0755 "$CAPTURE_DROPIN_DIR"
cat >"$CAPTURE_DROPIN" <<EOF_CAPTURE
[Service]
User=${CAPTURE_USER}
Group=${CAPTURE_GROUP}
NoNewPrivileges=true
CapabilityBoundingSet=
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
AmbientCapabilities=
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
ReadWritePaths=${PCAP_DIR}
EOF_CAPTURE
chmod 0644 "$CAPTURE_DROPIN"

for unit_file in "$SERVE_UNIT_DST" "$CAPTURE_UNIT_DST"; do
    if grep -Eq '^[[:space:]]*ExecStart=[[:space:]]*[-@:!]*\+' "$unit_file"; then
        die "$(basename "$unit_file") contains a privileged '+' ExecStart prefix."
    fi
done

systemctl daemon-reload

# ---------------------------------------------------------------------------
# 9. Validate effective systemd security properties
# ---------------------------------------------------------------------------

log "Validating systemd units and effective properties"
systemd-analyze verify "$SERVE_UNIT" "$CAPTURE_UNIT"

SERVE_EFFECTIVE_USER="$(systemctl show "$SERVE_UNIT" -p User --value)"
SERVE_EFFECTIVE_GROUP="$(systemctl show "$SERVE_UNIT" -p Group --value)"
SERVE_AMBIENT="$(systemctl show "$SERVE_UNIT" -p AmbientCapabilities --value)"
SERVE_PRIVATE_NETWORK="$(systemctl show "$SERVE_UNIT" -p PrivateNetwork --value 2>/dev/null || true)"

[[ "$SERVE_EFFECTIVE_USER" == "$SERVE_USER" ]] || die "$SERVE_UNIT effective User= is '$SERVE_EFFECTIVE_USER'."
[[ "$SERVE_EFFECTIVE_GROUP" == "$SERVE_GROUP" ]] || die "$SERVE_UNIT effective Group= is '$SERVE_EFFECTIVE_GROUP'."
[[ "$SERVE_PRIVATE_NETWORK" != "yes" ]] || die "$SERVE_UNIT has PrivateNetwork=yes, which prevents host-facing listeners."
if grep -Eqi '(^|[[:space:]])cap_net_(raw|admin)($|[[:space:]])' <<<"$SERVE_AMBIENT"; then
    die "$SERVE_UNIT unexpectedly receives packet-capture ambient capabilities: $SERVE_AMBIENT"
fi

CAPTURE_EFFECTIVE_USER="$(systemctl show "$CAPTURE_UNIT" -p User --value)"
CAPTURE_EFFECTIVE_GROUP="$(systemctl show "$CAPTURE_UNIT" -p Group --value)"
CAPTURE_NNP="$(systemctl show "$CAPTURE_UNIT" -p NoNewPrivileges --value)"
CAPTURE_BOUNDING="$(systemctl show "$CAPTURE_UNIT" -p CapabilityBoundingSet --value)"
CAPTURE_AMBIENT="$(systemctl show "$CAPTURE_UNIT" -p AmbientCapabilities --value)"
CAPTURE_PRIVATE_NETWORK="$(systemctl show "$CAPTURE_UNIT" -p PrivateNetwork --value 2>/dev/null || true)"
CAPTURE_RESTRICT_AF="$(systemctl show "$CAPTURE_UNIT" -p RestrictAddressFamilies --value 2>/dev/null || true)"

[[ "$CAPTURE_EFFECTIVE_USER" == "$CAPTURE_USER" ]] || die "$CAPTURE_UNIT effective User= is '$CAPTURE_EFFECTIVE_USER'."
[[ "$CAPTURE_EFFECTIVE_GROUP" == "$CAPTURE_GROUP" ]] || die "$CAPTURE_UNIT effective Group= is '$CAPTURE_EFFECTIVE_GROUP'."
[[ "$CAPTURE_NNP" == "yes" ]] || die "$CAPTURE_UNIT effective NoNewPrivileges= is '$CAPTURE_NNP'."
[[ "$CAPTURE_PRIVATE_NETWORK" != "yes" ]] || die "$CAPTURE_UNIT has PrivateNetwork=yes, which conflicts with host packet capture."

CAPTURE_BOUNDING_LC="${CAPTURE_BOUNDING,,}"
CAPTURE_AMBIENT_LC="${CAPTURE_AMBIENT,,}"
for cap in cap_net_raw cap_net_admin; do
    grep -qw "$cap" <<<"$CAPTURE_BOUNDING_LC" || die "$CAPTURE_UNIT CapabilityBoundingSet is missing $cap."
    grep -qw "$cap" <<<"$CAPTURE_AMBIENT_LC" || die "$CAPTURE_UNIT AmbientCapabilities is missing $cap."
done
[[ "$(wc -w <<<"$CAPTURE_BOUNDING")" -eq 2 ]] || die "$CAPTURE_UNIT has unexpected capabilities in CapabilityBoundingSet: $CAPTURE_BOUNDING"
[[ "$(wc -w <<<"$CAPTURE_AMBIENT")" -eq 2 ]] || die "$CAPTURE_UNIT has unexpected capabilities in AmbientCapabilities: $CAPTURE_AMBIENT"

if [[ -n "$CAPTURE_RESTRICT_AF" ]]; then
    grep -qw 'AF_PACKET' <<<"$CAPTURE_RESTRICT_AF" || die "$CAPTURE_UNIT RestrictAddressFamilies is missing AF_PACKET."
    grep -qw 'AF_UNIX' <<<"$CAPTURE_RESTRICT_AF" || die "$CAPTURE_UNIT RestrictAddressFamilies is missing AF_UNIX for capture.sock."
fi

# ---------------------------------------------------------------------------
# 10. Verify filesystem separation and TLS access
# ---------------------------------------------------------------------------

log "Validating service-account filesystem permissions"
runuser -u "$SERVE_USER" -- test -r "$CONFIG_DST" || die "$SERVE_USER cannot read $CONFIG_DST."
runuser -u "$CAPTURE_USER" -- test -r "$CONFIG_DST" || die "$CAPTURE_USER cannot read $CONFIG_DST."
runuser -u "$SERVE_USER" -- test -w "$JOURNAL_DIR" || die "$SERVE_USER cannot write $JOURNAL_DIR."
runuser -u "$SERVE_USER" -- test -w "$EVENTS_DIR" || die "$SERVE_USER cannot write $EVENTS_DIR."
runuser -u "$SERVE_USER" -- test -w "$INDEX_DIR" || die "$SERVE_USER cannot write $INDEX_DIR."
runuser -u "$CAPTURE_USER" -- test -w "$PCAP_DIR" || die "$CAPTURE_USER cannot write $PCAP_DIR."

if runuser -u "$CAPTURE_USER" -- test -r "$TLS_DIR"; then
    die "$CAPTURE_USER unexpectedly has read access to $TLS_DIR."
fi

if [[ -f "$TLS_KEY_DST" || -f "$TLS_CERT_DST" ]]; then
    [[ -f "$TLS_KEY_DST" && -f "$TLS_CERT_DST" ]] || die "Installed TLS material is incomplete."
    runuser -u "$SERVE_USER" -- test -r "$TLS_CERT_DST" || die "$SERVE_USER cannot read $TLS_CERT_DST."
    runuser -u "$SERVE_USER" -- test -r "$TLS_KEY_DST" || die "$SERVE_USER cannot read $TLS_KEY_DST."
    if runuser -u "$CAPTURE_USER" -- test -r "$TLS_KEY_DST"; then
        die "$CAPTURE_USER unexpectedly has read access to $TLS_KEY_DST."
    fi
fi

# ---------------------------------------------------------------------------
# 11. Isolated capture privilege smoke test
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
        -w "$SMOKE_FILE"; then
    rm -f -- "$SMOKE_FILE"
    die "Non-root dumpcap capability smoke test failed."
fi

[[ -s "$SMOKE_FILE" ]] || die "dumpcap smoke test did not create a PCAPNG file."
[[ "$(stat -c '%U:%G' "$SMOKE_FILE")" == "${CAPTURE_USER}:${CAPTURE_GROUP}" ]] || die "dumpcap smoke-test file has unexpected ownership."
rm -f -- "$SMOKE_FILE"

# ---------------------------------------------------------------------------
# 12. Validate application configuration and listener export
# ---------------------------------------------------------------------------

log "Running notAIhoney operational configuration validation"
CHECK_OUTPUT="$(mktemp)"
LISTENER_OUTPUT="$(mktemp)"
TMP_FILES+=("$CHECK_OUTPUT" "$LISTENER_OUTPUT")

if ! "$BINARY_DST" check --config "$CONFIG_DST" | tee "$CHECK_OUTPUT"; then
    die "notAIhoney operational configuration validation failed."
fi

log "Exporting validated listener definition"
if ! "$BINARY_DST" check \
    --config "$CONFIG_DST" \
    --emit-listeners=json \
    >"$LISTENER_OUTPUT"; then
    die "Listener export failed."
fi

jq -e . "$LISTENER_OUTPUT" >/dev/null || die "Listener export is not valid JSON."
CONFIG_SHA256="$(sha256sum "$CONFIG_DST" | awk '{print $1}')"
if ! jq -e --arg expected "$CONFIG_SHA256" '.. | strings | select(. == $expected)' "$LISTENER_OUTPUT" >/dev/null; then
    die "Listener export does not contain the installed configuration SHA-256 ($CONFIG_SHA256)."
fi
install -o root -g root -m 0644 "$LISTENER_OUTPUT" "$LISTENERS_JSON_DST"

# ---------------------------------------------------------------------------
# 13. Deterministic listener firewall generation and validation when available
# ---------------------------------------------------------------------------

FIREWALL_READY=0
if [[ -x "$NFT_GENERATOR_DST" ]]; then
    log "Generating nftables listener fragment from validated listener JSON"
    GENERATED_TMP="$(mktemp)"
    TMP_FILES+=("$GENERATED_TMP")
    "$NFT_GENERATOR_DST" <"$LISTENERS_JSON_DST" >"$GENERATED_TMP"
    [[ -s "$GENERATED_TMP" ]] || die "listeners-to-nft produced an empty nftables fragment."
    install -o root -g root -m 0644 "$GENERATED_TMP" "$GENERATED_NFT_DST"

    if ! grep -Fq 'generated-listeners.nft' "$BASE_NFT_DST"; then
        die "$BASE_NFT_DST does not reference generated-listeners.nft; refusing to treat the firewall as complete."
    fi

    nft -c -I "$INSTALL_ROOT" -f "$BASE_NFT_DST"
    FIREWALL_READY=1
else
    warn "No listeners-to-nft helper was supplied. Firewall listener generation is skipped rather than guessing a JSON-to-nft mapping."
fi

if (( APPLY_FIREWALL )); then
    (( FIREWALL_READY )) || die "--apply-firewall requires a supplied listeners-to-nft helper and a validated ruleset."
    NFT_BACKUP="/root/nftables-before-notaihoney-$(date -u +%Y%m%dT%H%M%SZ).nft"
    log "Saving current nftables ruleset to $NFT_BACKUP"
    nft list ruleset >"$NFT_BACKUP"
    warn "Applying the supplied notAIhoney nftables ruleset because --apply-firewall was explicitly requested."
    nft -I "$INSTALL_ROOT" -f "$BASE_NFT_DST"
fi

# ---------------------------------------------------------------------------
# 14. Start capture first, require READY hash, then start serving
# ---------------------------------------------------------------------------

if (( PREPARE_ONLY )); then
    log "Runtime installation and validation completed in prepare-only mode."
    printf '    binary:              %s\n' "$BINARY_DST"
    printf '    binary SHA-256:      %s\n' "$INSTALLED_SHA256"
    printf '    configuration:       %s\n' "$CONFIG_DST"
    printf '    config SHA-256:      %s\n' "$CONFIG_SHA256"
    printf '    listener export:     %s\n' "$LISTENERS_JSON_DST"
    printf '    firewall ready:      %s\n' "$([[ $FIREWALL_READY -eq 1 ]] && echo yes || echo no)"
    printf 'Services remain stopped and disabled because --prepare-only was requested.\n'
    exit 0
fi

log "Starting capture service"
ACTIVATION_STARTED=1
systemctl start "$CAPTURE_UNIT" || { show_service_diagnostics "$CAPTURE_UNIT"; die "Failed to start $CAPTURE_UNIT."; }
systemctl is-active --quiet "$CAPTURE_UNIT" || { show_service_diagnostics "$CAPTURE_UNIT"; die "$CAPTURE_UNIT is not active."; }

log "Waiting for capture READY with the installed configuration hash"
if ! runuser -u "$SERVE_USER" -- "$READY_HELPER"; then
    show_service_diagnostics "$CAPTURE_UNIT"
    die "Capture readiness validation failed."
fi

log "Starting serving service"
systemctl start "$SERVE_UNIT" || { show_service_diagnostics "$SERVE_UNIT"; die "Failed to start $SERVE_UNIT."; }
sleep 1
systemctl is-active --quiet "$SERVE_UNIT" || { show_service_diagnostics "$SERVE_UNIT"; die "$SERVE_UNIT is not active."; }
systemctl is-active --quiet "$CAPTURE_UNIT" || { show_service_diagnostics "$CAPTURE_UNIT"; die "$CAPTURE_UNIT stopped after serving startup."; }

log "Enabling services for boot"
systemctl enable "$CAPTURE_UNIT" "$SERVE_UNIT"
systemctl is-enabled --quiet "$CAPTURE_UNIT" || die "$CAPTURE_UNIT was not enabled."
systemctl is-enabled --quiet "$SERVE_UNIT" || die "$SERVE_UNIT was not enabled."

# Re-query readiness after serving startup to catch immediate capture loss.
runuser -u "$SERVE_USER" -- "$READY_HELPER" || { show_service_diagnostics "$CAPTURE_UNIT"; die "Capture READY state was lost after serving startup."; }

ACTIVATION_STARTED=0

printf '\n'
log "notAIhoney runtime deployment completed successfully."
printf '    binary:              %s\n' "$BINARY_DST"
printf '    binary SHA-256:      %s\n' "$INSTALLED_SHA256"
printf '    configuration:       %s\n' "$CONFIG_DST"
printf '    config SHA-256:      %s\n' "$CONFIG_SHA256"
printf '    listener export:     %s\n' "$LISTENERS_JSON_DST"
printf '    serving identity:    %s:%s\n' "$SERVE_USER" "$SERVE_GROUP"
printf '    capture identity:    %s:%s\n' "$CAPTURE_USER" "$CAPTURE_GROUP"
printf '    capture service:     active + enabled\n'
printf '    serving service:     active + enabled\n'
printf '    firewall generated:  %s\n' "$([[ $FIREWALL_READY -eq 1 ]] && echo yes || echo no)"
printf '    firewall applied:    %s\n' "$([[ $APPLY_FIREWALL -eq 1 ]] && echo yes || echo no)"
printf '\n'
ss -ltnp || true

if (( ! FIREWALL_READY )); then
    warn "The server is running, but the guide's production firewall gate is not satisfied until an approved listeners-to-nft helper is supplied and the final ruleset passes nft -c."
elif (( ! APPLY_FIREWALL )); then
    warn "The server is running and the firewall ruleset validates, but it was not loaded. Use --apply-firewall only after confirming management access and recovery."
fi
