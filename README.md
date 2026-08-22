# notAIhoney

**notAIhoney** is a Linux honeypot for exposed AI inference and model-serving APIs.

It simulates LLM inference engines, captures activity, and responds safely with synthetic data, with minimal resources (AWS Free Tier is 👍).

**Owner:** Denis Laskov  
**Year:** 2026  
**Current services:** Ollama, vLLM, Hugging Face TGI, llama.cpp server, TensorFlow Serving, NVIDIA NIM, NVIDIA Triton, and KServe API  
**Platform:** Ubuntu 24.04 LTS  
**License:** Free for personal use

---

## 1. What it does

The current version includes enabled and tested simulations for:

```text
Ollama               -> TCP/11434
vLLM                 -> TCP/8000
NVIDIA NIM           -> TCP/8000
NVIDIA Triton        -> TCP/8000
Hugging Face TGI     -> TCP/3000
llama.cpp server     -> TCP/8080
KServe API           -> TCP/8080
TensorFlow Serving   -> TCP/8501
```

> **Port conflicts:** vLLM, NVIDIA NIM, and NVIDIA Triton all use TCP/8000 in the current configuration, so on the same network interface only one of those three can be enabled at a time. llama.cpp server and KServe API both use TCP/8080, so on the same network interface only one of those two can be enabled at a time.

### Ollama

Supported Ollama API routes include:

```text
GET  /api/version
GET  /api/tags
GET  /api/ps
POST /api/show
POST /api/generate
POST /api/chat
```

### vLLM

Supported vLLM API routes include:

```text
GET  /health
GET  /ping
POST /ping
GET  /version
GET  /v1/models
```

### NVIDIA NIM

Supported NVIDIA NIM API routes include:

```text
GET  /v1/health/live
GET  /v1/health/ready
GET  /v1/models
GET  /v1/version
GET  /v1/metadata
POST /v1/chat/completions
POST /v1/completions
POST /v1/responses
```

### NVIDIA Triton

Supported NVIDIA Triton API routes include:

```text
GET  /v2/health/live
GET  /v2/health/ready
GET  /v2
POST /v2/repository/index
GET  /v2/models/simple/ready
GET  /v2/models/simple
GET  /v2/models/simple/config
POST /v2/models/simple/infer
```

### Hugging Face TGI

Supported Hugging Face TGI API routes include:

```text
GET  /health
GET  /info
GET  /v1/models
GET  /metrics
POST /generate
POST /generate_stream
POST /tokenize
POST /chat_tokenize
```

### llama.cpp server

Supported llama.cpp server API routes include:

```text
GET  /health
GET  /v1/health
GET  /props
GET  /slots
GET  /v1/models
POST /completion
POST /v1/completions
POST /v1/chat/completions
POST /tokenize
POST /detokenize
```

### KServe API

Supported KServe API routes include:

```text
GET  /v2/health/live
GET  /v2/health/ready
GET  /v2
GET  /v2/models/sklearn-iris/ready
GET  /v2/models/sklearn-iris
POST /v2/models/sklearn-iris/infer
GET  /v2/models/sklearn-iris/versions/1
POST /v1/models/sklearn-iris:predict
POST /v1/models/sklearn-iris:explain
```

### TensorFlow Serving

Supported TensorFlow Serving API routes include:

```text
GET  /
GET  /v1/models/saved_model_half_plus_three
GET  /v1/models/saved_model_half_plus_three/versions/123
GET  /v1/models/saved_model_half_plus_three/metadata
GET  /v1/models/saved_model_half_plus_three/versions/123/metadata
POST /v1/models/saved_model_half_plus_three:predict
POST /v1/models/saved_model_half_plus_three/versions/123:predict
POST /v1/models/saved_model_half_plus_three:regress
POST /v1/models/saved_model_half_plus_three:classify
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

The current Ubuntu deployment also expects native `nftables.service` **not** to be active or enabled. notAIhoney uses administrator-managed UFW for exposure of validated honeypot listener ports.

A Go compiler is **not required** when installing from a prebuilt release bundle.

---

## 3. How to install

Install the current Ubuntu 24.04 release in the following order.

### 1. Download the release archive

Download the release archive from:

```text
package/
```

### 2. Unpack the archive

Create or choose a directory for the release and extract the package:

```bash
tar -zxvf package.tar.gz
```

Then enter the extracted project directory.

### 3. Update the operating system

Before installing notAIhoney, update the package index and installed packages:

```bash
sudo apt update
sudo apt upgrade
```

### 4. Install Wireshark

Install Wireshark, which provides `dumpcap` for packet capture:

```bash
sudo apt install wireshark
```

### 5. Enter the scripts directory

```bash
cd scripts/
```

### 6. Prepare the system and configure dumpcap

Run both preparation scripts as superuser:

```bash
sudo ./prep_system.sh
sudo ./dumpcap_permissions.sh
```

`prep_system.sh` prepares the host prerequisites required by notAIhoney.

`dumpcap_permissions.sh` configures the packet-capture permissions required by the dedicated capture service.

### 7. Run the runtime installer

From the same `scripts/` directory, run:

```bash
sudo ./installer_ubuntu24_runtime.sh
```

The installer deploys the notAIhoney runtime, configuration, evidence directories, systemd services, capture configuration, listener validation, and firewall integration required by the current release.

### Cloud installations

When deploying notAIhoney in a cloud environment, update the instance or network **security group / firewall rules** to allow inbound access to the honeypot service ports you intend to expose:

```text
Ollama              -> TCP/11434
vLLM                -> TCP/8000
NVIDIA NIM          -> TCP/8000
NVIDIA Triton       -> TCP/8000
Hugging Face TGI    -> TCP/3000
llama.cpp server    -> TCP/8080
KServe API          -> TCP/8080
TensorFlow Serving  -> TCP/8501
```

Because vLLM, NVIDIA NIM, and NVIDIA Triton use the same TCP/8000 listener in the current configuration, exposing TCP/8000 allows whichever of those services is enabled. On the same network interface, only one of the three can listen on TCP/8000 at a time.

Likewise, llama.cpp server and KServe API both use TCP/8080. On the same network interface, only one of those two can listen on TCP/8080 at a time.

These cloud security-group rules are separate from the host firewall configuration on the Ubuntu machine.

After installation, verify the services:

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

1. Add support for multiple capture interfaces to support services that use the same port.
2. Add support for other operating systems.
3. Add a dashboard generator from JSONL files.
4. Add forensics and research scripts.
5. Support additional engines:
      1. SGLang
      2. ExLlamaV2
      3. MLC LLM
      4. Modular MAX Serve
      5. Friendli Engine
      6. Google JetStream
      7. MS DeepSpeed-FastGen
      8. Meta PyTorch / Llama Stack

---

## 6. Credits

**notAIhoney** was created and is maintained by **Denis Laskov**.

Copyright © 2026 Denis Laskov.

Free for personal, non-commercial use.

Commercial use, redistribution as part of a commercial product or service, or other commercial exploitation requires explicit permission from the owner.

The software is provided as-is, without warranty.
