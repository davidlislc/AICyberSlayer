# AICyberSlayer

> **Cross-platform security telemetry agent** — collects system metrics,
> network activity, forensic artefacts, and web server traffic then forwards
> everything to an Apache Kafka topic for AI-driven anomaly detection.
> Optional adapters push the same stream to Splunk, Elastic SIEM, or any
> syslog/CEF-compatible receiver.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        AICyberSlayer Agent                          │
│                                                                     │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌────────┐  │
│  │   System     │  │   Network    │  │  Forensics   │  │  Web   │  │
│  │  Collector   │  │  Collector   │  │  Collector   │  │ Server │  │
│  │ (CPU/Mem/    │  │ (NIC stats/  │  │ (fsnotify/   │  │Collect-│  │
│  │  Disk/Proc)  │  │  Sockets)    │  │  auth logs)  │  │  or)   │  │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └───┬────┘  │
│         └──────────────────┴──────────────────┴─────────────┘       │
│                                     │ event.Event                   │
│                              ┌──────▼──────┐                        │
│                              │    Agent    │                        │
│                              │ Orchestrator│                        │
│                              └──┬──────┬───┘                        │
│                                 │      │                            │
│                    ┌────────────▼─┐  ┌─▼───────────────────────┐   │
│                    │ Kafka Topic  │  │      SIEM Adapters        │   │
│                    │(aicyberslayer│  │  Splunk HEC | Elastic |  │   │
│                    │   by default)│  │  Syslog/CEF             │   │
│                    └─────────────┘  └─────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

**Technology choices**

| Concern | Choice | Rationale |
|---------|--------|-----------|
| Language | **Go 1.22+** | Single static binary, trivial cross-compile, low memory footprint, native concurrency |
| System metrics | [`gopsutil/v4`](https://github.com/shirou/gopsutil) | Cross-platform (Linux / macOS / Windows) without CGO |
| Kafka client | [`segmentio/kafka-go`](https://github.com/segmentio/kafka-go) | Pure-Go, no librdkafka dependency |
| FS watching | [`fsnotify`](https://github.com/fsnotify/fsnotify) | OS-native inotify/kqueue/FSEvents/ReadDirectory |
| Config | YAML + env overrides | Human-readable, secret-safe |
| Log format | `log/slog` JSON | Structured, machine-parseable |

---

## Project layout

```
AICyberSlayer/
├── cmd/agent/          # Main entry point
├── config/agent.yaml   # Default configuration
├── deployments/        # Docker-compose stack
├── internal/
│   ├── agent/          # Orchestrator (wires collectors + publishers)
│   ├── collector/      # system · network · forensics · webserver
│   ├── config/         # Config loader + validation
│   ├── kafka/          # Kafka producer (TLS + SASL-PLAIN/SCRAM)
│   └── siem/           # Splunk HEC · Elasticsearch · Syslog/CEF adapters
└── pkg/event/          # Canonical event types shared across packages
```

---

## Quick start

### Prerequisites

* Go 1.22 or later
* A reachable Kafka broker (see [Docker Compose](#docker-compose) for a
  one-liner local stack)

### Build

```bash
# Native binary
go build -o aicyberslayer-agent ./cmd/agent

# Cross-compile for Windows
GOOS=windows GOARCH=amd64 go build -o aicyberslayer-agent.exe ./cmd/agent

# Cross-compile for macOS (Apple Silicon)
GOOS=darwin GOARCH=arm64 go build -o aicyberslayer-agent-darwin-arm64 ./cmd/agent
```

### Configure

Copy and edit the sample configuration:

```bash
cp config/agent.yaml /etc/aicyberslayer/agent.yaml
$EDITOR /etc/aicyberslayer/agent.yaml
```

Sensitive values are read from environment variables so they never end up in
config files:

| Variable | Description |
|----------|-------------|
| `KAFKA_SASL_PASSWORD` | Kafka SASL password |
| `SPLUNK_HEC_TOKEN` | Splunk HTTP Event Collector token |
| `ELASTIC_PASSWORD` | Elasticsearch password |

### Run

```bash
./aicyberslayer-agent --config /etc/aicyberslayer/agent.yaml
```

---

## Docker Compose

A ready-to-use local stack (Kafka + agent) lives in `deployments/`:

```bash
cd deployments
docker compose up --build
```

Kafka will be reachable at `localhost:9092`; the agent topic is
`aicyberslayer` by default.

---

## Collectors

### System
Collects CPU utilisation, memory, disk partitions, and the full process
table (optional).  Published event types: `cpu_stats`, `mem_stats`,
`disk_stats`, `process_list`.

### Network
Reads NIC byte/packet counters and the kernel socket/connection table.
Published event types: `interface_stats`, `connection_table`.

### Forensics
* **Filesystem watcher** – uses OS-native events (inotify on Linux,
  FSEvents on macOS, ReadDirectoryChangesW on Windows) to stream
  create/write/delete/rename/chmod events from configured watch paths.
* **Login monitor** – parses `/var/log/auth.log` (Debian/Ubuntu) or
  `/var/log/secure` (RHEL/Fedora) to detect login, logout, and failed
  authentication events.

Published event types: `file_event`, `login_event`.

### Web server log
Tails nginx / Apache **Combined Log Format** access logs and emits one
event per HTTP request.  HTTP 4xx → `warning`; HTTP 5xx → `critical`.

Published event type: `http_access`.

---

## SIEM adapters

All adapters implement the `siem.Adapter` interface and are enabled
independently in the `siem:` section of the config.

| Adapter | Protocol | Notes |
|---------|----------|-------|
| **Splunk** | HTTPS to HEC `/services/collector/event` | Batch JSON; token via env var |
| **Elastic** | HTTPS to `/_bulk` | NDJSON; basic auth; custom index |
| **Syslog** | TCP or UDP | RFC 5424 or CEF (ArcSight) format |

---

## Kafka event schema

Every event is a JSON object with the following top-level fields:

```jsonc
{
  "id": "550e8400-e29b-41d4-a716-446655440000",  // UUID v4
  "timestamp": "2024-01-15T10:00:00Z",           // UTC RFC 3339
  "agent_id": "web-server-01",
  "hostname": "web-server-01.example.com",
  "os": "linux",
  "category": "system",           // system | network | forensics | webserver
  "type": "cpu_stats",            // event sub-type
  "severity": "info",             // debug | info | warning | critical
  "payload": { /* type-specific fields */ }
}
```

Events are keyed by `agent_id` so all events from the same machine land
in the same Kafka partition (ordered delivery).

---

## Configuration reference

See [`config/agent.yaml`](config/agent.yaml) for a fully annotated
example.  Key sections:

```yaml
agent:
  id: ""                  # defaults to hostname
  flush_interval: 30s     # collection & publish interval

kafka:
  brokers: ["localhost:9092"]
  topic: aicyberslayer
  tls:
    enabled: false
  sasl:
    enabled: false
    mechanism: PLAIN       # PLAIN | SCRAM-SHA-256 | SCRAM-SHA-512

collector:
  system:    { enabled: true,  collect_processes: true }
  network:   { enabled: true,  collect_connections: true }
  forensics: { enabled: true,  watch_paths: [/etc, /tmp], collect_logins: true }
  webserver: { enabled: false, log_files: [/var/log/nginx/access.log] }

siem:
  splunk:  { enabled: false }
  elastic: { enabled: false }
  syslog:  { enabled: false }
```

---

## Development

```bash
# Run all tests
go test ./...

# Build with race detector
go build -race ./...

# Vet
go vet ./...
```

---

## Supported platforms

| OS | Architecture |
|----|--------------|
| Linux | amd64, arm64 |
| macOS | amd64, arm64 |
| Windows | amd64 |

> **Note**: The forensics collector reads platform-specific auth logs
> (`/var/log/auth.log`, `/var/log/secure`, `/var/log/system.log`).
> Filesystem watching works out of the box on all three platforms.

