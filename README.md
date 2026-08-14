=# notAIhoney

**notAIhoney** is a modular Linux honeypot for exposed AI inference and model-serving HTTP/HTTPS APIs.

It is designed as a forensic and security-research sensor that impersonates AI-serving products, records interaction with them, and returns synthetic responses — without running a real LLM or executing attacker-controlled actions.

**Owner:** Denis Laskov  
**Year:** 2026  
**Status:** Work in progress  
**License:** Free for personal use

## Architecture

The project follows one core rule:

> **Go implements the generic honeypot engine; one YAML file defines all simulated AI services.**

The Go engine remains product-independent. All service-specific behavior — routes, responses, model information, headers, errors, delays, streaming behavior, and classifications — is defined in:

```text
config/honeypot.yaml
```

A new AI service should normally be added by extending the YAML configuration without changing Go code.

## Initial Scope

The first milestone simulates **Ollama** on its standard HTTP API surface, including:

```text
GET  /api/version
GET  /api/tags
GET  /api/ps
POST /api/show
POST /api/generate
POST /api/chat
```

Future YAML-defined services may include:

- vLLM
- NVIDIA NIM
- Hugging Face TGI
- llama.cpp server
- NVIDIA Triton
- TensorFlow Serving
- KServe-compatible APIs

Initial protocol support is **HTTP/1.1 and HTTPS**. HTTP/2 and gRPC may be added later when required for service fidelity.

## How It Works

```text
Internet
   |
   +----> dumpcap ----> PCAPNG
   |
   v
honeypotd
   |
   v
HTTP / HTTPS
   |
   v
Raw Request Recording
   |
   v
Generic Request Matcher
   |
   v
config/honeypot.yaml
   |
   v
Generic Response Engine
   |
   +----> Immediate JSON
   +----> NDJSON streaming
   +----> SSE streaming
   |
   v
Raw Response Recording
   |
   v
Client
```

## Evidence Collection

notAIhoney prioritizes forensic preservation and records activity at multiple levels:

- **PCAPNG** — authoritative network-level capture using `dumpcap`
- **Binary wire journal** — exact inbound and outbound application bytes
- **JSONL** — structured forensic events
- **SQLite** — optional local analytical index

Correlation IDs link connections, requests, responses, and evidence across these sources.

## Security Model

The honeypot records and synthetically responds to hostile activity but never performs the requested operation.

It must never provide:

- real LLM inference
- shell or command execution
- tool execution
- model downloads
- attacker-controlled URL fetching
- callbacks
- arbitrary outbound HTTP or DNS
- arbitrary file execution
- access to production systems
- outbound proxy functionality

The processing model is always:

```text
receive
  ↓
record
  ↓
parse
  ↓
match configuration
  ↓
synthetically respond
  ↓
record
```

## Project Structure

```text
notAIhoney/
├── cmd/
│   └── honeypotd/
│       └── main.go
├── internal/
│   ├── engine/
│   ├── config/
│   ├── response/
│   └── evidence/
├── config/
│   └── honeypot.yaml
├── tests/
├── go.mod
├── go.sum
├── README.md
└── LICENSE
```

## Requirements

- Linux
- Go
- `dumpcap`
- persistent local storage

No GPU, LLM runtime, Docker, Kubernetes, Redis, Kafka, or PostgreSQL is required.

The minimum performance target is:

```text
>= 5 requests/second per exposed port
```

## Design Principle

The architectural test for the project is simple:

> **Can a new AI HTTP service be added by changing only `config/honeypot.yaml`?**

If a Go change is required, it should introduce only a reusable generic engine capability — never product-specific behavior.

**Keep Go minimal and generic. Keep simulated service behavior in YAML. Record everything. Execute nothing.**

## License

Copyright © 2026 Denis Laskov.

Free for personal, non-commercial use. Commercial use or redistribution as part of a commercial product or service requires explicit permission from the owner.

The software is provided as-is, without warranty.
