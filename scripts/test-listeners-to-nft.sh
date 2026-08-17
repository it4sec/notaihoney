#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

PROJECT_ROOT=${PROJECT_ROOT:-"$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"}
SCRIPT=${SCRIPT:-"$PROJECT_ROOT/scripts/listeners-to-nft.sh"}
TMP_ROOT=${TMPDIR:-/tmp}/listeners-to-nft-tests.$$
mkdir -p "$TMP_ROOT"

cleanup() {
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
elements = { 11434 }
"

run_success \
    'single valid HTTPS listener' \
    '{"listeners":[{"service_id":"secure-service","address":"0.0.0.0","port":443,"protocol":"https"}]}' \
    $'elements = { 443 }\n'

mixed_http_https='{"listeners":[
  {"service_id":"http-service","address":"0.0.0.0","port":8080,"protocol":"http"},
  {"service_id":"https-service","address":"0.0.0.0","port":8443,"protocol":"https"}
]}'
run_success 'mixed HTTP + HTTPS listeners' "$mixed_http_https" $'elements = { 8080, 8443 }\n'

duplicate_http_https='{"listeners":[
  {"service_id":"http-service","address":"0.0.0.0","port":8443,"protocol":"http"},
  {"service_id":"https-service","address":"0.0.0.0","port":8443,"protocol":"https"}
]}'
run_success 'duplicate port across HTTP and HTTPS collapses' "$duplicate_http_https" $'elements = { 8443 }\n'

multiple='{"listeners":[
  {"service_id":"svc-a","address":"0.0.0.0","port":8080,"protocol":"http"},
  {"service_id":"svc-b","address":"0.0.0.0","port":11434,"protocol":"http"},
  {"service_id":"svc-c","address":"0.0.0.0","port":12000,"protocol":"http"}
]}'
run_success 'multiple valid listeners' "$multiple" $'elements = { 8080, 11434, 12000 }\n'

unordered='{"listeners":[
  {"service_id":"svc-c","address":"0.0.0.0","port":12000,"protocol":"http"},
  {"service_id":"svc-a","address":"0.0.0.0","port":8080,"protocol":"http"},
  {"service_id":"svc-b","address":"0.0.0.0","port":11434,"protocol":"http"}
]}'
run_success 'unordered listener input sorts numerically' "$unordered" $'elements = { 8080, 11434, 12000 }\n'

duplicates='{"listeners":[
  {"service_id":"svc-c","address":"0.0.0.0","port":12000,"protocol":"http"},
  {"service_id":"svc-a","address":"0.0.0.0","port":8080,"protocol":"http"},
  {"service_id":"svc-b","address":"0.0.0.0","port":11434,"protocol":"http"},
  {"service_id":"svc-a","address":"0.0.0.0","port":8080,"protocol":"http"}
]}'
run_success 'duplicate listener ports collapse' "$duplicates" $'elements = { 8080, 11434, 12000 }\n'

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

# Project integration check. This validates the generated fragment in the exact
# syntactic context where the supplied base.nft includes generated-listeners.nft.
#
# The production base.nft uses an absolute /etc/notaihoney include path. To keep
# this test non-destructive, make a temporary copy of base.nft and rewrite only
# that include path to a temporary generated fragment. The surrounding nftables
# table/set/chain structure remains unchanged.
default_base_nft="$PROJECT_ROOT/deploy/nftables/base.nft"
BASE_NFT=${BASE_NFT:-$default_base_nft}

if [[ -f $BASE_NFT ]]; then
    if ! command -v nft >/dev/null 2>&1; then
        fail 'nft integration check requested but nft is not installed'
    else
        integration_base="$TMP_ROOT/base.integration.nft"
        integration_generated="$TMP_ROOT/generated-listeners.nft"
        integration_error="$TMP_ROOT/integration-rewrite.error"

        if ! printf '%s' "$multiple" | "$SCRIPT" >"$integration_generated"; then
            fail 'failed to generate fragment for nft integration check'
        elif ! awk -v generated="$integration_generated" '
            BEGIN { replacements = 0 }
            /^[[:space:]]*include[[:space:]]+"\/etc\/notaihoney\/generated-listeners\.nft"[[:space:]]*$/ {
                indent = $0
                sub(/include.*/, "", indent)
                print indent "include \"" generated "\""
                replacements++
                next
            }
            { print }
            END {
                if (replacements != 1) {
                    print "expected exactly one /etc/notaihoney/generated-listeners.nft include, found " replacements > "/dev/stderr"
                    exit 42
                }
            }
        ' "$BASE_NFT" >"$integration_base" 2>"$integration_error"; then
            fail "could not prepare base.nft integration copy: $(<"$integration_error")"
        elif nft -c -f "$integration_base"; then
            pass 'generated set fragment passes nft -c in supplied base.nft include context'
        else
            fail 'generated set fragment failed nft -c in supplied base.nft include context'
        fi
    fi
else
    printf '%s\n' '# SKIP nft -c integration: deploy/nftables/base.nft is absent; or set BASE_NFT explicitly.'
fi

printf '%s\n' "# passed: $pass_count; failed: $fail_count"
((fail_count == 0))
