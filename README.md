# notAIhoney

**notAIhoney** is a Linux honeypot for exposed AI inference and model-serving APIs.

It presents believable AI-service endpoints, records network and application activity, and returns synthetic responses without running a real LLM or executing attacker-controlled actions.

**Owner:** Denis Laskov  
**Year:** 2026  
**Current milestone:** Ollama emulation  
**Platform:** Ubuntu 24.04 LTS  
**License:** Free for personal use

---

## 1. What it does

The current version simulates an **Ollama** service, normally exposed on:

```text
TCP/11434
```

Supported API routes include:

```text
GET  /api/version
GET  /api/tags
GET  /api/ps
POST /api/show
POST /api/generate
POST /api/chat
```

notAIhoney records activity at several levels:

- **PCAPNG** — packet-level network evidence captured by `dumpcap`
- **BWJ** — exact application-level inbound and outbound bytes
- **JSONL** — structured forensic events
- **SQLite** — optional offline analytical index built from collected evidence

The honeypot does not execute attacker requests. It does not perform real inference, run tools or commands, download models, fetch attacker-controlled URLs, or act as an outbound proxy.

---

## 2. Prerequisites

This release is intended for an **isolated Ubuntu 24.04 LTS amd64/x86_64 host** using systemd.

Required:

- root or `sudo` access
- an active network interface available for packet capture
- `dumpcap` / Wireshark capture components
- persistent local storage for evidence
- systemd
- **UFW installed and already active**

The installer does not own the host firewall configuration. It must not enable, disable, restart, or reconfigure UFW globally.

The current Ubuntu deployment also expects native `nftables.service` **not** to be active or enabled. notAIhoney uses administrator-managed UFW for exposure of validated honeypot listener ports.

A Go compiler is **not required** when installing from a prebuilt release bundle.

---

## 3. How to install

Extract the notAIhoney release archive and enter the extracted directory.

The release bundle contains the prebuilt binary, configuration, systemd services, and installer.

Run:

```bash
sudo ./installer_ubuntu24_runtime.sh
```

The installer performs the required runtime setup, including:

- dependency and host validation
- creation of the `notaihoney` runtime identities
- installation of the binary and YAML configuration
- evidence-directory preparation
- capture-interface selection
- `dumpcap` permission validation
- installation of the capture and serving systemd services
- capture readiness validation
- configuration and operational checks
- validated listener export

### Firewall application

Public listener exposure is an explicit installation step.

When firewall application is requested, the installer derives the required TCP ports from:

```text
honeypot.yaml
    ↓
notaihoney validation
    ↓
validated listener JSON
    ↓
generated UFW application profile
```

The generated profile is stored under:

```text
/etc/ufw/applications.d/notaihoney
```

Only the notAIhoney UFW application rule is managed by the installer.

The installer must not modify global UFW policy or native nftables configuration.

After installation, verify:

```bash
sudo systemctl status notaihoney-capture.service
sudo systemctl status notaihoney.service
```

The capture service must be healthy before the public honeypot service is allowed to run.

---

## 4. How to use the output files

The main evidence directory is:

```text
/var/lib/notaihoney/
```

### Packet capture

```text
/var/lib/notaihoney/pcap/
```

Contains PCAPNG files produced by `dumpcap`.

Use these files with tools such as Wireshark or tshark to inspect connection attempts, TCP behavior, malformed traffic, retransmissions, resets, and complete network conversations.

### Binary Wire Journal

```text
/var/lib/notaihoney/journal/
```

Contains the application-level wire journal.

BWJ preserves the exact bytes observed by the honeypot before and after HTTP processing and is useful when reconstructing individual request/response exchanges.

### JSON output example

A sample structured JSON event output is shown below:

![notAIhoney JSON output example](samples/json_img.png)

### Structured events

```text
/var/lib/notaihoney/events/
```

Contains JSONL event files.

These are the easiest files to use for searching activity, filtering requests, identifying source IPs, reviewing matched routes and classifications, and correlating requests with responses.

Example:

```bash
jq . /var/lib/notaihoney/events/*.jsonl
```

### Offline SQLite index

```text
/var/lib/notaihoney/index/
```

SQLite is a derived analytical format and is not authoritative evidence.

The index can be created or refreshed offline with the `index` mode of the `notaihoney` binary.

### Collecting evidence

Project deployment tooling also includes an evidence-collection workflow for archiving the current contents of the notAIhoney evidence directories without stopping the running sensor.

Collected archives should be stored outside `/var/lib/notaihoney`, under the invoking administrator's home directory.

---

## 5. Next steps

The current milestone is focused on completing and validating the Ollama sensor.

Planned work includes:

- complete Milestone 1 fixture validation
- continue malformed, slow-client, load, and resource-limit testing
- improve deployment and evidence-handling validation
- expand forensic analysis and indexing workflows
- add additional AI-service simulations through `honeypot.yaml`

Planned future service targets include:

- vLLM
- NVIDIA NIM
- Hugging Face TGI
- llama.cpp server
- NVIDIA Triton
- TensorFlow Serving
- KServe-compatible APIs

The guiding rule remains:

> **Keep the Go engine small and generic, keep simulated service behavior in one YAML file, preserve evidence, and execute nothing requested by the attacker.**

---

## 6. Credits

**notAIhoney** was created and is maintained by **Denis Laskov**.

Copyright © 2026 Denis Laskov.

Free for personal, non-commercial use.

Commercial use, redistribution as part of a commercial product or service, or other commercial exploitation requires explicit permission from the owner.

The software is provided as-is, without warranty.
