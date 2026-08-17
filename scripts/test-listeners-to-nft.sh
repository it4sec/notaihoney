#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

PROJECT_ROOT=${PROJECT_ROOT:-"$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"}
SCRIPT=${SCRIPT:-"$PROJECT_ROOT/scripts/listeners-to-nft.sh"}
TMP_ROOT=${TMPDIR:-/tmp}/listeners-to-nft-tests.$$
mkdir -p "$TMP_ROOT"

integration_restore_path=
integration_backup_path=
integration_had_original=0

cleanup() {
    if [[ -n $integration_restore_path ]]; then
        if ((integration_had_original)); then
            cp -- "$integration_backup_path" "$integration_restore_path" 2>/dev/null || :
        else
            rm -f -- "$integration_restore_path" 2>/dev/null || :
        fi
    fi
    rm -rf -- "$TMP_ROOT"
}
trap cleanup EXIT

pass_count=0
fail_count=0

pass() {
    printf 'ok - %s\n' "$1"
    pass_count=$((pass_count + 1))
}

fail() {
    printf 'not ok - %s\n' "$1" >&2
    fail_count=$((fail_count + 1))
}

run_success() {
    local name=$1
    local input=$2
    local expected=$3
    local actual_file="$TMP_ROOT/actual"
    local expected_file="$TMP_ROOT/expected"
    local error_file="$TMP_ROOT/error"

    if ! printf '%s' "$input" | "$SCRIPT" >"$actual_file" 2>"$error_file"; then
        fail "$name (unexpected failure: $(<"$error_file"))"
        return
    fi

    printf '%s' "$expected" >"$expected_file"
    if cmp -s "$expected_file" "$actual_file"; then
        pass "$name"
    else
        fail "$name (output mismatch)"
        printf '%s\n' '--- expected ---' >&2
        cat "$expected_file" >&2
        printf '%s\n' '--- actual ---' >&2
        cat "$actual_file" >&2
    fi
}

run_failure() {
    local name=$1
    local input=$2
    local actual_file="$TMP_ROOT/actual"
    local error_file="$TMP_ROOT/error"

    if printf '%s' "$input" | "$SCRIPT" >"$actual_file" 2>"$error_file"; then
        fail "$name (unexpected success)"
        return
    fi

    if [[ -s $actual_file ]]; then
        fail "$name (partial stdout was emitted)"
        return
    fi

    if [[ ! -s $error_file ]]; then
        fail "$name (no diagnostic on stderr)"
        return
    fi

    pass "$name"
}

valid_hash=5ece571b68ea6c42948a44abf28b236d97516f14baf4ef86be057f1eecc56999

run_success \
    'single valid TCP-backed listener' \
    "{\"config_sha256\":\"$valid_hash\",\"listeners\":[{\"service_id\":\"ollama\",\"address\":\"0.0.0.0\",\"port\":11434,\"protocol\":\"http\"}]}" \
    "# source configuration SHA-256: $valid_hash
tcp dport { 11434 } accept
"

run_success \
    'single valid HTTPS listener' \
    '{"listeners":[{"service_id":"secure-service","address":"0.0.0.0","port":443,"protocol":"https"}]}' \
    $'tcp dport { 443 } accept\n'

mixed_http_https='{"listeners":[
  {"service_id":"http-service","address":"0.0.0.0","port":8080,"protocol":"http"},
  {"service_id":"https-service","address":"0.0.0.0","port":8443,"protocol":"https"}
]}'
run_success 'mixed HTTP + HTTPS listeners' "$mixed_http_https" $'tcp dport { 8080, 8443 } accept\n'

duplicate_http_https='{"listeners":[
  {"service_id":"http-service","address":"0.0.0.0","port":8443,"protocol":"http"},
  {"service_id":"https-service","address":"0.0.0.0","port":8443,"protocol":"https"}
]}'
run_success 'duplicate port across HTTP and HTTPS collapses' "$duplicate_http_https" $'tcp dport { 8443 } accept\n'

multiple='{"listeners":[
  {"service_id":"svc-a","address":"0.0.0.0","port":8080,"protocol":"http"},
  {"service_id":"svc-b","address":"0.0.0.0","port":11434,"protocol":"http"},
  {"service_id":"svc-c","address":"0.0.0.0","port":12000,"protocol":"http"}
]}'
run_success 'multiple valid listeners' "$multiple" $'tcp dport { 8080, 11434, 12000 } accept\n'

unordered='{"listeners":[
  {"service_id":"svc-c","address":"0.0.0.0","port":12000,"protocol":"http"},
  {"service_id":"svc-a","address":"0.0.0.0","port":8080,"protocol":"http"},
  {"service_id":"svc-b","address":"0.0.0.0","port":11434,"protocol":"http"}
]}'
run_success 'unordered listener input sorts numerically' "$unordered" $'tcp dport { 8080, 11434, 12000 } accept\n'

duplicates='{"listeners":[
  {"service_id":"svc-c","address":"0.0.0.0","port":12000,"protocol":"http"},
  {"service_id":"svc-a","address":"0.0.0.0","port":8080,"protocol":"http"},
  {"service_id":"svc-b","address":"0.0.0.0","port":11434,"protocol":"http"},
  {"service_id":"svc-a","address":"0.0.0.0","port":8080,"protocol":"http"}
]}'
run_success 'duplicate listener ports collapse' "$duplicates" $'tcp dport { 8080, 11434, 12000 } accept\n'

run_failure 'invalid JSON' '{"listeners":['
run_failure 'empty input' ''
run_failure 'missing listener collection' '{"config_sha256":"5ece571b68ea6c42948a44abf28b236d97516f14baf4ef86be057f1eecc56999"}'
run_failure 'missing port' '{"listeners":[{"service_id":"x","address":"0.0.0.0","protocol":"http"}]}'
run_failure 'port = 0' '{"listeners":[{"service_id":"x","address":"0.0.0.0","port":0,"protocol":"http"}]}'
run_failure 'port = 65536' '{"listeners":[{"service_id":"x","address":"0.0.0.0","port":65536,"protocol":"http"}]}'
run_failure 'negative port' '{"listeners":[{"service_id":"x","address":"0.0.0.0","port":-1,"protocol":"http"}]}'
run_failure 'non-numeric port' '{"listeners":[{"service_id":"x","address":"0.0.0.0","port":"11434","protocol":"http"}]}'
run_failure 'unsupported protocol' '{"listeners":[{"service_id":"x","address":"0.0.0.0","port":11434,"protocol":"udp"}]}'
run_failure 'invalid address' '{"listeners":[{"service_id":"x","address":"999.0.0.1","port":11434,"protocol":"http"}]}'
run_failure 'unexpected input structure' '{"listeners":{"service_id":"x","address":"0.0.0.0","port":11434,"protocol":"http"}}'
run_failure 'unexpected listener field' '{"listeners":[{"service_id":"x","address":"0.0.0.0","port":11434,"protocol":"http","extra":true}]}'
run_failure 'injection-style port value' '{"listeners":[{"service_id":"x","address":"0.0.0.0","port":"11434; flush ruleset","protocol":"http"}]}'
run_failure 'injection-style address value' '{"listeners":[{"service_id":"x","address":"0.0.0.0; flush ruleset","port":11434,"protocol":"http"}]}'
run_failure 'invalid SHA-256 metadata' '{"config_sha256":"not-a-sha256","listeners":[{"service_id":"x","address":"0.0.0.0","port":11434,"protocol":"http"}]}'

# Byte-for-byte determinism, including the final newline.
printf '%s' "$multiple" | "$SCRIPT" >"$TMP_ROOT/order-a.nft"
printf '%s' "$unordered" | "$SCRIPT" >"$TMP_ROOT/order-b.nft"
if cmp -s "$TMP_ROOT/order-a.nft" "$TMP_ROOT/order-b.nft"; then
    pass 'logically equivalent listener ordering is byte-for-byte identical'
else
    fail 'logically equivalent listener ordering is byte-for-byte identical'
fi

# Project integration check. Explicit BASE_NFT/GENERATED_NFT values take
# precedence. Otherwise, automatically use the real project paths when
# deploy/nftables/base.nft exists. The generated file is restored afterward so
# this test does not leave the working tree modified.
default_base_nft="$PROJECT_ROOT/deploy/nftables/base.nft"
default_generated_nft="$PROJECT_ROOT/deploy/nftables/generated-listeners.nft"
integration_requested=0

if [[ -n ${BASE_NFT:-} || -n ${GENERATED_NFT:-} ]]; then
    integration_requested=1
    if [[ -z ${BASE_NFT:-} || -z ${GENERATED_NFT:-} ]]; then
        fail 'nft integration check requires both BASE_NFT and GENERATED_NFT'
        integration_requested=0
    fi
elif [[ -f $default_base_nft ]]; then
    BASE_NFT=$default_base_nft
    GENERATED_NFT=$default_generated_nft
    integration_requested=1
fi

if ((integration_requested)); then
    if ! command -v nft >/dev/null 2>&1; then
        fail 'nft integration check requested but nft is not installed'
    elif [[ ! -f $BASE_NFT ]]; then
        fail "nft integration check base file does not exist: $BASE_NFT"
    elif [[ ! -d $(dirname -- "$GENERATED_NFT") ]]; then
        fail "nft integration check generated-file directory does not exist: $(dirname -- "$GENERATED_NFT")"
    else
        integration_restore_path=$GENERATED_NFT
        integration_backup_path="$TMP_ROOT/generated-listeners.original"
        integration_had_original=0
        if [[ -e $GENERATED_NFT ]]; then
            cp -- "$GENERATED_NFT" "$integration_backup_path"
            integration_had_original=1
        fi

        if ! printf '%s' "$multiple" | "$SCRIPT" >"$GENERATED_NFT"; then
            fail 'failed to generate fragment for nft integration check'
        elif nft -c -I "$(dirname -- "$BASE_NFT")" -f "$BASE_NFT"; then
            pass 'generated fragment passes nft -c with supplied base.nft'
        else
            fail 'generated fragment failed nft -c with supplied base.nft'
        fi

        if ((integration_had_original)); then
            cp -- "$integration_backup_path" "$GENERATED_NFT"
        else
            rm -f -- "$GENERATED_NFT"
        fi
        integration_restore_path=
    fi
else
    printf '%s\n' '# SKIP nft -c integration: deploy/nftables/base.nft is absent; or set BASE_NFT and GENERATED_NFT explicitly.'
fi

printf '%s\n' "# passed: $pass_count; failed: $fail_count"
((fail_count == 0))
