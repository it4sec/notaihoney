# notAIhoney

**notAIhoney** is a small, standalone Linux honeypot for exposed AI inference and model-serving APIs.

It impersonates AI services, preserves network and application evidence, and returns deterministic synthetic responses without running a real LLM or executing attacker-controlled actions.

**Owner:** Denis Laskov  
**Year:** 2026  
**Architecture:** v1.3  
**Implementation:** Go  
**License:** Free for personal use

---

## Current Status

Milestone 1 is focused on **Ollama emulation** and has progressed from architecture into implementation and Ubuntu runtime deployment validation.

The current project includes:

- Go-based `notaihoney` executable
- `serve`, `capture`, `check`, and offline `index` modes
- one strict global YAML configuration
- Ollama API simulation on TCP/11434
- HTTP/1.0 and HTTP/1.1 support
- HTTPS carrying HTTP/1.1
- immediate and NDJSON response modes
- PCAPNG capture through `dumpcap`
- Binary Wire Journal (BWJ) evidence
- structured JSONL events
- optional offline SQLite indexing
- separate systemd units for serving and packet capture
- capture readiness through `/run/notaihoney/capture.sock`
- validated listener export for firewall generation
- Ubuntu 24.04 runtime installer and release packaging

Runtime deployment validation has reached successful capture readiness, configuration/operational checks, listener export, firewall-rule generation/validation, and active serving/capture services.

Firewall loading remains an explicit deployment action rather than an automatic side effect.

---

## Core Design

notAIhoney follows three project principles:

1. **Keep the engine simple.**
2. **Run as a standalone sandboxed sensor.**
3. **Keep all operator-configurable behavior in one YAML file.**

The central architecture rule is:

> **Go implements generic honeypot mechanisms. `honeypot.yaml` defines simulated service behavior.**

Product-specific routes, versions, model identities, responses, delays, classifications, and fallback behavior must not be hardcoded in Go.

A future AI service should normally be added by extending:

```text
config/honeypot.yaml
```

without modifying the Go engine.

---

## Milestone 1 — Ollama

The first simulated service is Ollama.

Configured routes include:

```text
GET  /api/version
GET  /api/tags
GET  /api/ps

POST /api/show
POST /api/generate
POST /api/chat
```

The configured fake service remains internally consistent across discovery, metadata, inference, and streaming responses.

No real inference is performed.

---

## Runtime Architecture

```text
Internet
   |
   +-----------------------> notaihoney capture
   |                              |
   |                           dumpcap
   |                              |
   |                           PCAPNG
   |                              |
   |                    /run/notaihoney/capture.sock
   |                              |
   v                              v
notaihoney serve <----------------+
   |
HTTP / HTTPS
   |
BWJ plaintext recording
   |
Go HTTP/1.x parser
   |
method + raw-path matcher
   |
/etc/notaihoney/honeypot.yaml
   |
generic response engine
   |
immediate / NDJSON
   |
BWJ outbound evidence
   |
Client
   |
bounded JSONL events

offline:
JSONL + BWJ -> optional SQLite index
```

The serving process does not require packet-capture privileges. Packet capture is isolated into a separate runtime identity and service.

---

## Single YAML Configuration

Source configuration:

```text
config/honeypot.yaml
```

Installed configuration:

```text
/etc/notaihoney/honeypot.yaml
```

The YAML owns:

- sensor identity
- evidence locations
- resource limits
- listeners
- service identity
- routes
- classifications
- response sequences
- HTTP status codes
- response headers
- response bodies
- timing
- NDJSON chunks
- fallback responses

The exact configuration bytes are identified by `config_sha256`.

Capture and serving must use the same configuration revision.

---

## Evidence Model

Milestone 1 uses three live evidence layers:

```text
PCAPNG + BWJ + JSONL
```

**PCAPNG** preserves authoritative network-level evidence using `dumpcap`.

**Binary Wire Journal (BWJ)** preserves exact application plaintext bytes observed by `notaihoney`. For HTTPS, PCAP contains encrypted network traffic while BWJ contains decrypted HTTP plaintext after TLS termination.

**JSONL** stores bounded structured forensic events and correlation information.

**SQLite** is optional and offline only. It is derived from preserved evidence and is not part of the live serving request path.

---

## Capture Safety Contract

Public listeners must not operate without healthy packet capture.

The capture service exposes:

```text
/run/notaihoney/capture.sock
```

and reports readiness for the current `config_sha256`.

If capture is unavailable or loses health, the serving process fails closed rather than continuing to attract traffic without required raw evidence.

The Linux capture sandbox requires the address families needed for:

```text
AF_PACKET
AF_UNIX
AF_NETLINK
```

and only the packet-capture capabilities required by `dumpcap`.

---

## Security Model

notAIhoney never executes attacker intent.

The serving path must never perform:

- real LLM inference
- shell execution
- arbitrary command execution
- tool execution
- model downloads
- attacker-controlled URL requests
- callbacks
- arbitrary outbound HTTP, DNS, or TCP
- arbitrary file execution
- access to production systems
- proxy or tunnel behavior

Every interaction follows:

```text
receive
   ↓
preserve
   ↓
parse
   ↓
classify / match
   ↓
synthetically respond
   ↓
preserve
```

---

## Executable

The project produces one binary:

```text
/usr/local/bin/notaihoney
```

Milestone 1 modes:

```bash
notaihoney serve   --config /etc/notaihoney/honeypot.yaml
notaihoney capture --config /etc/notaihoney/honeypot.yaml
notaihoney check   --config /etc/notaihoney/honeypot.yaml
notaihoney index   --config /etc/notaihoney/honeypot.yaml
```

Validated listener information can be exported for deployment tooling:

```bash
notaihoney check \
  --config /etc/notaihoney/honeypot.yaml \
  --emit-listeners=json
```

---

## Deployment

The runtime currently targets Ubuntu 24.04 LTS.

Main installed paths:

```text
/usr/local/bin/notaihoney

/etc/notaihoney/
├── honeypot.yaml
├── base.nft
├── listeners.json
└── generated-listeners.nft

/run/notaihoney/
└── capture.sock

/var/lib/notaihoney/
├── pcap/
├── journal/
├── events/
└── index/
```

Service separation:

```text
notaihoney-capture.service
        ↓
notaihoney capture
        ↓
dumpcap
        ↓
capture READY
        ↓
notaihoney.service
        ↓
notaihoney serve
        ↓
public listeners
```

The deployment tooling validates capture permissions, runtime directories, service hardening, configuration, listener export, and firewall inputs before considering the runtime ready.

Firewall changes require explicit operator approval/application.

---

## Repository Structure

```text
notaihoney/
├── cmd/
│   └── notaihoney/
│       └── main.go
├── internal/
│   ├── config/
│   ├── engine/
│   ├── response/
│   ├── evidence/
│   ├── capture/
│   └── index/
├── config/
│   └── honeypot.yaml
├── deploy/
│   ├── systemd/
│   │   ├── notaihoney.service
│   │   └── notaihoney-capture.service
│   └── nftables/
│       └── base.nft
├── scripts/
│   ├── installer_ubuntu24_runtime.sh
│   ├── listeners-to-nft.sh
│   └── packer.sh
├── tests/
├── go.mod
├── go.sum
├── README.md
└── LICENSE
```

---

## Requirements

Build/runtime requirements include:

- Linux
- Go 1.23.2 for the current reproducible build baseline
- CGO-enabled build environment
- C compiler/toolchain
- `dumpcap`
- persistent local evidence storage
- systemd for the current deployment model

No GPU or real LLM runtime is required.

The architecture target remains:

```text
>= 5 requests/second per exposed service port
```

with bounded behavior for malformed, slow, oversized, and long-lived connections.

---

## Future Services

The same engine is intended to support additional YAML-defined AI HTTP services such as:

- vLLM
- NVIDIA NIM
- Hugging Face TGI
- llama.cpp server
- NVIDIA Triton
- TensorFlow Serving
- KServe-compatible services

Go changes are acceptable only when a new service requires a **generic reusable engine capability**.

---

## Guiding Rule

> **Keep the daemon small and generic. Keep configuration in one YAML file. Preserve raw evidence before interpretation. Execute nothing requested by the attacker.**

---

