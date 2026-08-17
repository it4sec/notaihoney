#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

error() {
    printf '[ERROR] %s\n' "$1" >&2
    exit 1
}

require_jq() {
    command -v jq >/dev/null 2>&1 || error 'Required dependency not found: jq'
}

# Structural validation only. Listener binding/exposure semantics are owned by
# honeypot.yaml and the Go application. This generator intentionally accepts any
# canonical IPv4 address from the validated export and remains port-set based.
validate_ipv4_address() {
    local address=$1
    local octet
    local -a octets=()
    local IFS='.'

    [[ $address =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    read -r -a octets <<< "$address"
    ((${#octets[@]} == 4)) || return 1

    for octet in "${octets[@]}"; do
        # Reject ambiguous leading-zero forms such as 010.0.0.1.
        [[ $octet == 0 || $octet =~ ^[1-9][0-9]{0,2}$ ]] || return 1
        ((10#$octet <= 255)) || return 1
    done
}

jq_true() {
    jq -e "$1" <<< "$json" >/dev/null 2>&1
}

require_jq

# Slurp first so jq, rather than Bash, validates the raw byte stream. This also
# lets us reject empty input and multiple top-level JSON documents explicitly.
if ! json_documents=$(jq -cs '.' 2>/dev/null); then
    error 'Input is not valid JSON.'
fi

json_document_count=$(jq -r 'length' <<< "$json_documents")
case $json_document_count in
    0)
        error 'Input is empty.'
        ;;
    1)
        ;;
    *)
        error 'Expected exactly one top-level JSON document.'
        ;;
esac

json=$(jq -c '.[0]' <<< "$json_documents")
unset json_documents

jq_true 'type == "object"' || error 'Unexpected input structure: top-level JSON value must be an object.'

# Implement the exact observed upstream schema. config_sha256 is optional;
# listeners is required. Unknown top-level fields fail closed.
jq_true '((keys_unsorted - ["config_sha256", "listeners"]) | length) == 0' \
    || error 'Unexpected input structure: unknown top-level field.'
jq_true 'has("listeners")' || error 'Missing listener collection: listeners.'
jq_true '(.listeners | type) == "array"' || error 'Unexpected input structure: listeners must be an array.'
jq_true '(.listeners | length) > 0' || error 'Listener collection must contain at least one listener.'

if jq_true 'has("config_sha256")'; then
    jq_true '(.config_sha256 | type) == "string" and (.config_sha256 | test("^[0-9A-Fa-f]{64}$"))' \
        || error 'Invalid config_sha256: expected exactly 64 hexadecimal characters.'
fi

listener_count=$(jq -r '.listeners | length' <<< "$json")

for ((i = 0; i < listener_count; i++)); do
    display_index=$((i + 1))

    jq_true ".listeners[$i] | type == \"object\"" \
        || error "Listener $display_index has unexpected structure: expected an object."

    for field in service_id address port protocol; do
        jq_true ".listeners[$i] | has(\"$field\")" \
            || error "Listener $display_index is missing required field: $field"
    done

    jq_true ".listeners[$i] | ((keys_unsorted - [\"service_id\", \"address\", \"port\", \"protocol\"]) | length) == 0" \
        || error "Listener $display_index has unexpected field(s)."

    jq_true ".listeners[$i].service_id | type == \"string\"" \
        || error "Listener $display_index contains invalid service_id: expected a string."
    service_id=$(jq -r ".listeners[$i].service_id" <<< "$json")
    [[ $service_id =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]] \
        || error "Listener $display_index contains invalid service_id syntax."

    jq_true ".listeners[$i].address | type == \"string\"" \
        || error "Listener $display_index contains invalid address: expected a string."
    address=$(jq -r ".listeners[$i].address" <<< "$json")
    validate_ipv4_address "$address" \
        || error "Listener $display_index contains invalid address; expected canonical IPv4 dotted-decimal syntax."

    jq_true ".listeners[$i].protocol | type == \"string\"" \
        || error "Listener $display_index contains invalid protocol: expected a string."
    protocol=$(jq -r ".listeners[$i].protocol" <<< "$json")
    case $protocol in
        http|https)
            # The upstream schema uses application-level protocol labels. Both
            # supported values are TCP-backed and therefore contribute only
            # their validated port number to the nftables listener_ports set.
            ;;
        *)
            error "Listener $display_index contains unsupported protocol; supported TCP-backed protocols are 'http' and 'https'."
            ;;
    esac

    jq_true ".listeners[$i].port | type == \"number\"" \
        || error "Listener $display_index contains invalid TCP port: expected an integer from 1 to 65535."
    jq_true ".listeners[$i].port as \$p | (\$p == (\$p | floor)) and (\$p >= 1) and (\$p <= 65535)" \
        || error "Listener $display_index contains invalid TCP port: expected an integer from 1 to 65535."
done

# Build the complete fragment in memory only after every listener has passed
# validation. No configuration bytes are written to stdout on validation error.
if ! fragment=$(jq -r '
    ([.listeners[].port | floor] | sort | unique) as $ports
    | (if has("config_sha256") then
           "# source configuration SHA-256: " + (.config_sha256 | ascii_downcase) + "\n"
       else
           ""
       end)
      + "elements = { " + ($ports | map(tostring) | join(", ")) + " }"
' <<< "$json"); then
    error 'Failed to generate nftables fragment.'
fi

printf '%s\n' "$fragment"
