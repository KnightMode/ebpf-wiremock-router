# ebpf-wiremock-router

Transparently redirect your application's outgoing TCP connections to local WireMock instances using eBPF — **zero application config changes required**.

## How It Works

```
Your App ──connect(any-host)──► eBPF redirects ALL TCP ──► Transparent Proxy
                                                              │
                                            ┌─────────────────┼─────────────────┐
                                            │                 │                 │
                                    Host: service-a    Host: service-b    Unknown host
                                            │                 │                 │
                                      WireMock :8080   WireMock :8081   Real destination
```

1. An eBPF program hooks `connect()` syscalls via `cgroup/connect4`
2. **ALL** outgoing IPv4 TCP connections are redirected to a local transparent proxy
3. The proxy inspects the HTTP `Host` header (or TLS SNI) to determine the target service
4. Known hosts are routed to the correct WireMock port; unknown hosts pass through to the real destination
5. The app has no idea — it thinks it's talking to the real service

## Requirements

- **Linux** kernel 4.17+ with BPF and cgroup v2 support
- **Go** 1.22+
- **clang/llvm** for compiling eBPF C
- **bpftool** for generating vmlinux.h
- **Root/sudo** for loading eBPF programs

### Install dependencies

Ubuntu/Debian:
```bash
sudo apt install clang llvm libbpf-dev linux-tools-common linux-tools-$(uname -r)
```

Fedora:
```bash
sudo dnf install clang llvm libbpf-devel bpftool
```

## Quick Start

### 1. Configure `wiremock.yaml`

```yaml
services:
  order-api:
    port: 8080
    originals:
      default: https://service-a.example.com

  inventory-api:
    port: 8081
    originals:
      default: https://service-b.example.com

  notification-api:
    port: 8082
    originals:
      default: https://service-c.example.com
```

Each service maps an `originals` URL hostname to a local WireMock port. The proxy extracts the hostname from each URL and routes matching traffic to that port.

### 2. Start WireMock instances

```bash
# Using WireMock CLI
wiremock run --port 8080 --root-dir .wiremock/order-api
wiremock run --port 8081 --root-dir .wiremock/inventory-api
wiremock run --port 8082 --root-dir .wiremock/notification-api
```

### 3. Build and run

```bash
make build
sudo ./ebpf-wiremock-router -wiremock wiremock.yaml
```

### 4. Run your app normally

```bash
# Your app connects to service-a.example.com as usual
# eBPF intercepts the connection → proxy routes to WireMock :8080
./your-app
```

## Docker Integration

A `docker-compose.yaml` is included for running the full stack (WireMock + eBPF router + test runner) in containers:

```bash
docker compose up --build
```

The test runner container uses `privileged` mode and `network_mode: "service:wiremock"` to share the network namespace with WireMock.

## CLI Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-wiremock` | `wiremock.yaml` | Path to wiremock.yaml |
| `-cgroup` | `/sys/fs/cgroup` | Cgroup v2 path to attach eBPF to |
| `-proxy-port` | `16789` | Port for the transparent proxy |
| `-metadata-addr` | `:9667` | Address for the metadata/correlation API |
| `-verbose` | `false` | Enable verbose logging |

## Test Metadata Correlation

The router includes a metadata API that correlates which tests hit which services. A JUnit 5 extension (`EbpfTestExtension`) reports test lifecycle events to the metadata API, and the router matches connections to active tests by timestamp.

After tests complete, a dependency report is printed:

```
=== Test → Service Dependency Report ===

  testCreateOrder
    → service-a.example.com
    → service-b.example.com

  testCancelOrder
    → service-a.example.com
    → service-b.example.com
    → service-c.example.com
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  Userspace                                                      │
│                                                                 │
│  ┌───────────────┐     ┌──────────────────────────┐            │
│  │ wiremock.yaml │────►│  ebpf-wiremock-router     │            │
│  └───────────────┘     │  (Go controller)          │            │
│                        │  - builds host→port map   │            │
│                        │  - starts transparent     │            │
│                        │    proxy on :16789        │            │
│                        │  - writes PID/port to     │            │
│                        │    BPF maps               │            │
│                        │  - attaches to cgroup     │            │
│                        └──────────┬────────────────┘            │
│                                   │                             │
│  ┌────────────────────────────────▼──────────────────────────┐  │
│  │  Transparent Proxy (:16789)                               │  │
│  │  - Peeks at incoming bytes                                │  │
│  │  - 0x16 → TLS: extract SNI hostname                      │  │
│  │  - Otherwise: extract HTTP Host header                    │  │
│  │  - Known host → forward to WireMock port                  │  │
│  │  - Unknown host → pass-through to real destination        │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│  Kernel                                                         │
│                                                                 │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  eBPF: connect4_redirect (cgroup/connect4)                │  │
│  │                                                           │  │
│  │  - Intercepts ALL outgoing IPv4 TCP connect() calls       │  │
│  │  - Skips: loopback (127.0.0.0/8), UDP, proxy's own PID   │  │
│  │  - Rewrites destination → 127.0.0.1:<proxy_port>         │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Key Design Decisions

- **Redirect ALL traffic**: Instead of matching specific IPs/ports in eBPF, redirect everything to the proxy. The proxy has full visibility into HTTP headers and TLS SNI, making routing decisions much more flexible.
- **Pass-through for unknown hosts**: Traffic to hosts not in `wiremock.yaml` (e.g., Maven Central, Docker registries) flows through to the real destination unmodified.
- **Dummy /etc/hosts entries**: For fake hostnames (e.g., `service-a.example.com`), the router injects dummy IPs from `198.18.0.0/15` into `/etc/hosts` so DNS resolves and `connect()` fires (which eBPF then intercepts).
- **TCP-only filtering**: The eBPF program only intercepts `SOCK_STREAM` (TCP), leaving DNS (UDP) untouched.
- **Loopback skip**: Connections to `127.0.0.0/8` are skipped to avoid intercepting WireMock traffic, Docker's internal DNS (`127.0.0.11`), and the proxy's own backend connections.

## License

GPL-2.0 (required for eBPF programs)
