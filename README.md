# notAIhoney

`notAIhoney` is a small Linux honeypot for exposed AI model-serving HTTP APIs. It receives attacker traffic, preserves forensic evidence, parses and classifies requests, and returns YAML-defined synthetic responses without executing attacker intent or performing real model inference.

Milestone 1 implements one Go executable with four modes:

```text
notaihoney serve   --config /etc/notaihoney/honeypot.yaml
notaihoney capture --config /etc/notaihoney/honeypot.yaml
notaihoney check   --config /etc/notaihoney/honeypot.yaml
notaihoney index   --config /etc/notaihoney/honeypot.yaml
```

Validated listener data for firewall generation is exported with:

```text
notaihoney check --config /etc/notaihoney/honeypot.yaml --emit-listeners=json
```

## Design

- One strict YAML configuration file controls service identities, listeners, routes, classifications, response data, sequences and timing.
- Production Go code contains only generic mechanisms and no product-specific routing behavior.
- Live evidence is PCAPNG + Binary Wire Journal (BWJ) + bounded JSONL.
- BWJ records inbound plaintext before the Go HTTP parser may consume it.
- SQLite is an optional offline index built from preserved JSONL and BWJ evidence.
- Packet capture is a separate process mode supervised through `/run/notaihoney/capture.sock`; serving fails closed if capture readiness is absent or lost.
- Plain HTTP supports HTTP/1.0 and HTTP/1.1. HTTPS uses TLS 1.2–1.3 and application HTTP/1.1 only.
- The serving process never proxies, downloads, invokes shells, runs attacker-controlled commands, or initiates attacker-controlled outbound connections.

## Configuration

The repository configuration is `config/honeypot.yaml`; the production location is `/etc/notaihoney/honeypot.yaml`.

The exact bytes of the YAML file are SHA-256 hashed as `config_sha256`. Comments and whitespace are therefore part of the configuration revision identity.

Some Milestone 1 service responses intentionally retain `__VERIFIED_FIXTURE_REQUIRED__`. Those markers are data-level placeholders for externally verified response fixtures; the generic engine does not special-case them.

## Evidence

PCAPNG captures network-level traffic. BWJ stores exact plaintext application bytes processed by the daemon. JSONL stores bounded structured interpretation with sensitive header/query values represented safely rather than duplicated as raw secrets. `notaihoney index` reconstructs BWJ streams and derives request SHA-256 values offline.

Evidence is never automatically deleted, overwritten, or purged to recover disk space.

## Deployment

Reference systemd units and nftables files live under `deploy/`. The serving and capture identities are intentionally separated. Listener ports in nftables must be generated from validated listener export rather than manually copied from YAML.
