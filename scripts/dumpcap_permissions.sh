#!/usr/bin/env bash
#
# configure-notaihoney-dumpcap.sh
#
# Configure Ubuntu 24.04 LTS so notaihoney-capture.service can execute
# dumpcap as the dedicated non-root notaihoney-capture account using only:
#
#   CAP_NET_RAW
#   CAP_NET_ADMIN
#
# The script deliberately removes filesystem capabilities and setuid/setgid
# privilege from dumpcap. The capabilities are supplied by systemd instead.
#
# Run as root:
#   sudo ./configure-notaihoney-dumpcap.sh
#
# Optional:
#   sudo ./configure-notaihoney-dumpcap.sh --start-service
#
# The optional flag starts/restarts notaihoney-capture.service after the
# configuration and verifies that dumpcap is running as notaihoney-capture.
#

set -Eeuo pipefail
IFS=$'\n\t'

SERVICE="notaihoney-capture.service"
MAIN_SERVICE="notaihoney.service"
CAPTURE_USER="notaihoney-capture"
CAPTURE_GROUP="notaihoney-capture"
PCAP_DIR="/var/lib/notaihoney/pcap"

DROPIN_DIR="/etc/systemd/system/${SERVICE}.d"
DROPIN_FILE="${DROPIN_DIR}/20-dumpcap-capabilities.conf"

START_SERVICE=0

log() {
    printf '[+] %s\n' "$*"
}

warn() {
    printf '[!] %s\n' "$*" >&2
}

die() {
    printf '[ERROR] %s\n' "$*" >&2
    exit 1
}

usage() {
    cat <<EOF
Usage: $0 [--start-service]

Options:
  --start-service   Start/restart ${SERVICE} after configuration and perform
                    runtime process checks.
  -h, --help        Show this help.

Without --start-service, the script configures and validates the permissions,
runs a short isolated dumpcap capture smoke test, and leaves the service's
running/stopped state unchanged.
EOF
}

while (($#)); do
    case "$1" in
        --start-service)
            START_SERVICE=1
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            usage >&2
            die "Unknown argument: $1"
            ;;
    esac
    shift
done

[[ ${EUID} -eq 0 ]] || die "Run this script as root."

# ---------------------------------------------------------------------------
# Platform and prerequisite checks
# ---------------------------------------------------------------------------

[[ -r /etc/os-release ]] || die "/etc/os-release is missing."
# shellcheck disable=SC1091
source /etc/os-release

if [[ "${ID:-}" != "ubuntu" || "${VERSION_ID:-}" != "24.04" ]]; then
    die "This script is intended for Ubuntu 24.04 LTS. Detected: ${PRETTY_NAME:-unknown}."
fi

for cmd in systemctl systemd-analyze systemd-run journalctl getent groupadd \
           useradd usermod id install stat chmod chown pgrep ps grep find rm cp \
           date cut wc awk; do
    command -v "$cmd" >/dev/null 2>&1 || die "Required command not found: $cmd"
done

# libcap2-bin supplies setcap, getcap and capsh.
if ! command -v setcap >/dev/null 2>&1 || \
   ! command -v getcap >/dev/null 2>&1 || \
   ! command -v capsh >/dev/null 2>&1; then
    log "Installing libcap2-bin..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y libcap2-bin
fi

DUMPCAP="$(command -v dumpcap || true)"
[[ -n "$DUMPCAP" ]] || die \
    "dumpcap is not installed. Install the Ubuntu dumpcap/Wireshark package first, then rerun this script."

[[ -f "$DUMPCAP" ]] || die "dumpcap path is not a regular file: $DUMPCAP"

DUMPCAP_UID="$(stat -c '%u' "$DUMPCAP")"
[[ "$DUMPCAP_UID" == "0" ]] || die \
    "Refusing to modify $DUMPCAP because it is not owned by root."

# Ubuntu/Debian's wireshark-common package can reapply group-based file
# capabilities during package configuration if this debconf setting is true.
# Seed it to false so future package upgrades preserve the systemd-owned
# privilege model rather than restoring global dumpcap file capabilities.
if command -v dpkg-query >/dev/null 2>&1 && \
   dpkg-query -W -f='${Status}' wireshark-common 2>/dev/null | grep -q 'install ok installed'; then
    command -v debconf-set-selections >/dev/null 2>&1 || die \
        "wireshark-common is installed but debconf-set-selections is unavailable."

    log "Disabling package-managed non-root dumpcap file privileges"
    printf '%s\n' \
        'wireshark-common wireshark-common/install-setuid boolean false' \
        | debconf-set-selections
fi

systemctl cat "$SERVICE" >/dev/null 2>&1 || die \
    "${SERVICE} is not installed. Install the notAIhoney systemd unit before running this script."

# Reject an ExecStart= command explicitly prefixed with '+' because '+' tells
# systemd to execute that command with elevated/full privilege behavior rather
# than the service's normal credential restrictions.
if systemctl cat "$SERVICE" | grep -Eq '^[[:space:]]*ExecStart=[[:space:]]*[-@:!]*\+'; then
    die "${SERVICE} contains an ExecStart= command with the systemd '+' privilege prefix. Remove it first."
fi

# ---------------------------------------------------------------------------
# Dedicated capture identity
# ---------------------------------------------------------------------------

if ! getent group "$CAPTURE_GROUP" >/dev/null; then
    log "Creating system group: $CAPTURE_GROUP"
    groupadd --system "$CAPTURE_GROUP"
fi

if ! id "$CAPTURE_USER" >/dev/null 2>&1; then
    log "Creating system user: $CAPTURE_USER"
    useradd \
        --system \
        --gid "$CAPTURE_GROUP" \
        --home-dir /nonexistent \
        --no-create-home \
        --shell /usr/sbin/nologin \
        "$CAPTURE_USER"
else
    CURRENT_PRIMARY_GROUP="$(id -gn "$CAPTURE_USER")"
    if [[ "$CURRENT_PRIMARY_GROUP" != "$CAPTURE_GROUP" ]]; then
        log "Setting primary group for $CAPTURE_USER to $CAPTURE_GROUP"
        usermod --gid "$CAPTURE_GROUP" "$CAPTURE_USER"
    fi

    CURRENT_SHELL="$(getent passwd "$CAPTURE_USER" | cut -d: -f7)"
    if [[ "$CURRENT_SHELL" != "/usr/sbin/nologin" ]]; then
        log "Setting non-login shell for $CAPTURE_USER"
        usermod --shell /usr/sbin/nologin "$CAPTURE_USER"
    fi
fi

# ---------------------------------------------------------------------------
# Capture output directory
# ---------------------------------------------------------------------------

log "Preparing capture directory: $PCAP_DIR"
install -d \
    -o "$CAPTURE_USER" \
    -g "$CAPTURE_GROUP" \
    -m 0750 \
    "$PCAP_DIR"

# ---------------------------------------------------------------------------
# Make dumpcap an ordinary executable: no file capabilities, no setuid/setgid
# ---------------------------------------------------------------------------

log "Removing filesystem capabilities from $DUMPCAP"
setcap -r "$DUMPCAP" 2>/dev/null || true

# Normalize to the package's non-privileged state: root:root, mode 0755.
# Execution itself is not privileged; packet-capture privilege will come only
# from systemd.
chown root:root "$DUMPCAP"
chmod 0755 "$DUMPCAP"

if [[ -n "$(getcap "$DUMPCAP" 2>/dev/null)" ]]; then
    die "Filesystem capabilities are still present on $DUMPCAP."
fi

MODE="$(stat -c '%a' "$DUMPCAP")"
[[ "$MODE" == "755" ]] || die \
    "Unexpected mode on $DUMPCAP after normalization: $MODE"

# ---------------------------------------------------------------------------
# systemd capability configuration
# ---------------------------------------------------------------------------

log "Writing systemd capability drop-in: $DROPIN_FILE"
install -d -o root -g root -m 0755 "$DROPIN_DIR"

if [[ -e "$DROPIN_FILE" ]]; then
    BACKUP="${DROPIN_FILE}.bak.$(date +%Y%m%d%H%M%S)"
    cp -a "$DROPIN_FILE" "$BACKUP"
    log "Backed up previous drop-in to: $BACKUP"
fi

cat >"$DROPIN_FILE" <<EOF
[Service]
User=${CAPTURE_USER}
Group=${CAPTURE_GROUP}

# The process and its children may not acquire additional privilege through
# execve(), setuid/setgid binaries, or filesystem capabilities.
NoNewPrivileges=true

# Reset any earlier capability assignments and permit exactly the two
# capabilities required for normal Linux packet capture.
CapabilityBoundingSet=
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN

# Supply those capabilities to this non-root service and its normal children.
AmbientCapabilities=
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN

# Ensure the configured capture path remains writable even if the base unit
# uses ProtectSystem= or related filesystem hardening.
ReadWritePaths=${PCAP_DIR}
EOF

chmod 0644 "$DROPIN_FILE"

log "Reloading systemd"
systemctl daemon-reload

FRAGMENT_PATH="$(systemctl show "$SERVICE" -p FragmentPath --value)"
[[ -n "$FRAGMENT_PATH" && -f "$FRAGMENT_PATH" ]] || die \
    "Could not determine the unit fragment path for $SERVICE."

log "Validating systemd unit syntax"
systemd-analyze verify "$FRAGMENT_PATH"

# ---------------------------------------------------------------------------
# Effective configuration checks
# ---------------------------------------------------------------------------

SERVICE_USER="$(systemctl show "$SERVICE" -p User --value)"
SERVICE_GROUP="$(systemctl show "$SERVICE" -p Group --value)"
SERVICE_NNP="$(systemctl show "$SERVICE" -p NoNewPrivileges --value)"
SERVICE_BOUNDING="$(systemctl show "$SERVICE" -p CapabilityBoundingSet --value)"
SERVICE_AMBIENT="$(systemctl show "$SERVICE" -p AmbientCapabilities --value)"
PRIVATE_NETWORK="$(systemctl show "$SERVICE" -p PrivateNetwork --value 2>/dev/null || true)"
RESTRICT_AF="$(systemctl show "$SERVICE" -p RestrictAddressFamilies --value 2>/dev/null || true)"

[[ "$SERVICE_USER" == "$CAPTURE_USER" ]] || die \
    "Effective service User= is '$SERVICE_USER', expected '$CAPTURE_USER'."

[[ "$SERVICE_GROUP" == "$CAPTURE_GROUP" ]] || die \
    "Effective service Group= is '$SERVICE_GROUP', expected '$CAPTURE_GROUP'."

[[ "$SERVICE_NNP" == "yes" ]] || die \
    "Effective NoNewPrivileges= is '$SERVICE_NNP', expected 'yes'."

for cap in cap_net_raw cap_net_admin; do
    grep -qw "$cap" <<<"$SERVICE_BOUNDING" || die \
        "CapabilityBoundingSet is missing $cap: $SERVICE_BOUNDING"
    grep -qw "$cap" <<<"$SERVICE_AMBIENT" || die \
        "AmbientCapabilities is missing $cap: $SERVICE_AMBIENT"
done

# Because the drop-in resets both sets, no unrelated capabilities should remain.
BOUNDING_WORDS="$(wc -w <<<"$SERVICE_BOUNDING")"
AMBIENT_WORDS="$(wc -w <<<"$SERVICE_AMBIENT")"

[[ "$BOUNDING_WORDS" -eq 2 ]] || die \
    "CapabilityBoundingSet contains more than the two expected capabilities: $SERVICE_BOUNDING"

[[ "$AMBIENT_WORDS" -eq 2 ]] || die \
    "AmbientCapabilities contains more than the two expected capabilities: $SERVICE_AMBIENT"

if [[ "$PRIVATE_NETWORK" == "yes" ]]; then
    die "${SERVICE} has PrivateNetwork=yes. That isolates it from the host network namespace and conflicts with host packet capture."
fi

if [[ -n "$RESTRICT_AF" && "$RESTRICT_AF" != *AF_PACKET* ]]; then
    warn "${SERVICE} restricts address families and AF_PACKET is not visible in the effective list:"
    warn "RestrictAddressFamilies=$RESTRICT_AF"
    warn "Packet capture may fail unless the base unit permits AF_PACKET."
fi

# ---------------------------------------------------------------------------
# Isolated non-root capture smoke test
# ---------------------------------------------------------------------------

SMOKE_FILE="${PCAP_DIR}/.dumpcap-permission-smoke-test.pcapng"
rm -f "$SMOKE_FILE"

log "Running a one-second non-root dumpcap smoke test through systemd"

SMOKE_UNIT="notaihoney-dumpcap-smoke-${$}.service"

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
    rm -f "$SMOKE_FILE"
    die "Non-root dumpcap smoke test failed."
fi

[[ -s "$SMOKE_FILE" ]] || {
    rm -f "$SMOKE_FILE"
    die "dumpcap smoke test did not produce a capture file."
}

SMOKE_OWNER="$(stat -c '%U:%G' "$SMOKE_FILE")"
[[ "$SMOKE_OWNER" == "${CAPTURE_USER}:${CAPTURE_GROUP}" ]] || warn \
    "Smoke-test file owner is $SMOKE_OWNER; expected ${CAPTURE_USER}:${CAPTURE_GROUP}."

rm -f "$SMOKE_FILE"

# ---------------------------------------------------------------------------
# Main service safety check
# ---------------------------------------------------------------------------

if systemctl cat "$MAIN_SERVICE" >/dev/null 2>&1; then
    MAIN_USER="$(systemctl show "$MAIN_SERVICE" -p User --value)"
    MAIN_AMBIENT="$(systemctl show "$MAIN_SERVICE" -p AmbientCapabilities --value)"

    if [[ -z "$MAIN_USER" || "$MAIN_USER" == "root" ]]; then
        warn "${MAIN_SERVICE} appears to run as root. The intended architecture says the main serving process should be unprivileged."
    fi

    if grep -Eq '(^|[[:space:]])cap_net_(raw|admin)($|[[:space:]])' <<<"$MAIN_AMBIENT"; then
        warn "${MAIN_SERVICE} has packet-capture ambient capabilities: $MAIN_AMBIENT"
        warn "Remove those capabilities from the main serving service."
    fi
fi

# ---------------------------------------------------------------------------
# Optional actual service start/restart and runtime identity verification
# ---------------------------------------------------------------------------

if [[ "$START_SERVICE" -eq 0 ]] && systemctl is-active --quiet "$SERVICE"; then
    warn "$SERVICE is currently active. Its running process still has the old credential/capability state."
    warn "Restart it after review, or rerun this script with --start-service."
fi

if [[ "$START_SERVICE" -eq 1 ]]; then
    log "Starting/restarting $SERVICE"
    systemctl restart "$SERVICE"

    if ! systemctl is-active --quiet "$SERVICE"; then
        systemctl --no-pager --full status "$SERVICE" || true
        journalctl -u "$SERVICE" -b --no-pager -n 100 || true
        die "$SERVICE did not become active."
    fi

    sleep 1

    mapfile -t DUMPCAP_PIDS < <(pgrep -u "$CAPTURE_USER" -x dumpcap || true)

    if ((${#DUMPCAP_PIDS[@]} == 0)); then
        warn "$SERVICE is active, but no running dumpcap process owned by $CAPTURE_USER was found."
        warn "This can be normal only if the service starts dumpcap on demand or dumpcap exits after short capture jobs."
    else
        log "Running dumpcap process(es):"
        ps -o pid,user,group,cmd -p "$(IFS=,; echo "${DUMPCAP_PIDS[*]}")"

        for pid in "${DUMPCAP_PIDS[@]}"; do
            if [[ -r "/proc/$pid/status" ]]; then
                CAP_EFF="$(awk '/^CapEff:/ {print $2}' "/proc/$pid/status")"
                CAP_AMB="$(awk '/^CapAmb:/ {print $2}' "/proc/$pid/status")"

                printf '    PID %s CapEff: %s\n' "$pid" "$CAP_EFF"
                capsh --decode="$CAP_EFF" || true

                printf '    PID %s CapAmb: %s\n' "$pid" "$CAP_AMB"
                capsh --decode="$CAP_AMB" || true
            fi
        done
    fi
fi

# ---------------------------------------------------------------------------
# Final report
# ---------------------------------------------------------------------------

printf '\n'
log "Configuration complete."
printf '\n'
printf 'dumpcap path:                 %s\n' "$DUMPCAP"
printf 'dumpcap file capabilities:    %s\n' "$(getcap "$DUMPCAP" 2>/dev/null || true)"
printf 'dumpcap mode/owner:           %s\n' "$(stat -c '%A %U:%G' "$DUMPCAP")"
printf 'capture service user:         %s\n' "$SERVICE_USER"
printf 'capture service group:        %s\n' "$SERVICE_GROUP"
printf 'NoNewPrivileges:              %s\n' "$SERVICE_NNP"
printf 'CapabilityBoundingSet:        %s\n' "$SERVICE_BOUNDING"
printf 'AmbientCapabilities:          %s\n' "$SERVICE_AMBIENT"
printf 'capture directory:            %s\n' "$PCAP_DIR"
printf 'capture directory ownership:  %s\n' "$(stat -c '%A %U:%G' "$PCAP_DIR")"
printf 'systemd drop-in:              %s\n' "$DROPIN_FILE"
printf '\n'

if [[ "$START_SERVICE" -eq 0 ]]; then
    printf 'The service was not started by this script.\n'
    printf 'To start it and run the runtime checks:\n'
    printf '  sudo %s --start-service\n' "$0"
fi
