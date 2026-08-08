# EventHorizon

**EventHorizon** is an open-source framework for deploying and analyzing multiprotocol IoT tarpits.  
It provides a modular, containerized environment where each protocol emulator runs inside its own Docker container, 
and all telemetry data is collected and visualized through a Prometheus + Grafana stack.

### 🌌 Why the name *EventHorizon*?
In astrophysics, the *event horizon* is the boundary around a black hole beyond which nothing can escape.  
Similarly, the **EventHorizon** framework acts as a boundary for malicious network activity:  
once an automated scanner crosses into it, the connection cannot progress or escape—it becomes trapped indefinitely.  
This captures the essence of what the framework does: slowing, containing, and observing automated attacks without letting them spread.

---

## 🚀 Quick start

```bash
git clone https://github.com/<your-fork>/EventHorizon.git
cd EventHorizon
docker compose up -d --build
```

Then check that everything works:

```bash
./scripts/smoke.sh
```

The smoke test starts the stack, opens one Telnet connection, and confirms the
exporter counted it. It prints `SMOKE PASSED` and leaves the stack running.

Stop everything with `docker compose down`.

## What you get

| Service | Address | Purpose |
| --- | --- | --- |
| Grafana | http://127.0.0.1:3000 | Dashboards (`EventHorizon Metrics` is the current one) |
| Prometheus | http://127.0.0.1:9090 | Metric storage |
| Exporter | http://127.0.0.1:9101/metrics | Raw metrics from the tarpits |
| Telnet tarpit | port 23 | |
| MQTT tarpit | port 1883 | |
| UPnP tarpit | ports 1900 (SSDP), 8080 (HTTP) | |
| CoAP tarpit | port 5683 | |
| SSH tarpit | port 22 | vendored `endlessh` |

Ports and per-protocol limits live in [`.env`](.env). The tarpits default to the
real service ports, because that is where scanners look for them — **if your own
`sshd` listens on port 22, change `SSH_PORT` before starting the stack.** See
[`DEPLOYMENT.md`](DEPLOYMENT.md).

## Checking it by hand

The smoke test is just these steps in a loop:

```bash
# The exporter is serving metrics
curl -s http://127.0.0.1:9101/metrics | grep total_connects

# Trap yourself in the Telnet tarpit (Ctrl-C to escape)
nc 127.0.0.1 23

# The connection was counted
curl -s http://127.0.0.1:9101/metrics | grep 'total_connects{server="Telnet"}'

# Prometheus and Grafana are healthy
curl -s http://127.0.0.1:9090/-/healthy
curl -s http://127.0.0.1:3000/api/health
```

[`METRICS.md`](METRICS.md) documents every metric the exporter publishes.

## Development

```bash
make all               # build the tarpit binaries and the Go exporter
make test              # C unit tests
make test-go           # Go exporter tests and vet
make check-dashboards  # Grafana panels match the exporter's metric surface
make smoke             # the smoke test above
```

CI runs exactly these checks plus the smoke test.

## Deploying on a server

See [`DEPLOYMENT.md`](DEPLOYMENT.md). EventHorizon is a honeypot: read the
exposure warning there before putting it on a public IP.
