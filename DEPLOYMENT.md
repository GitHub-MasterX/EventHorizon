# Deploying EventHorizon on a server

EventHorizon deploys as a plain Docker Compose stack. There is no deployment
tool to learn: you clone the repository on the host, adjust `.env`, and bring
Compose up. Everything below is done over SSH on the target machine.

## ⚠️ Exposure warning

EventHorizon is a honeypot. Its tarpits are meant to accept connections from
hostile automated scanners, and once running on a public IP the host **will**
be scanned and attacked. Only deploy on a machine you are authorized to expose,
that carries no other production workload, and that you can afford to rebuild.

Publishing a tarpit is a separate decision from getting the stack running.
Bring it up bound to localhost first, confirm it works, and only then open
ports in your provider's firewall.

## Requirements

- Linux host with Docker Engine and the Compose plugin, x86-64 or arm64
- Ports listed in `.env` free on the host
- x86-64 specifically if you use `docker-compose.field.yml`; that overlay pins
  its images to `linux/amd64`

## 1. Get the source

```bash
git clone https://github.com/<your-fork>/EventHorizon.git
cd EventHorizon
```

## 2. Check the ports

`.env` puts the tarpits on the real service ports, because that is where
scanners look for them:

| Variable | Default | |
| --- | --- | --- |
| `TELNET_PORT` | 23 | |
| `SSH_PORT` | 22 | **collides with the host's own `sshd`** |
| `MQTT_PORT` | 1883 | |
| `COAP_PORT` | 5683 | |
| `UPNP_SSDP_PORT` / `UPNP_HTTP_PORT` | 1900 / 8080 | |

**The SSH tarpit defaults to port 22.** If your own `sshd` listens there, the
`endlessh` container will fail to start, and moving `sshd` out of the way
carelessly can lock you out of the machine. Do one of these before starting:

```bash
# Either: move the tarpit somewhere harmless
SSH_PORT=2222

# Or: move your real sshd first, reconnect on the new port, and only then
# leave SSH_PORT=22 for the tarpit
```

Verify the ports are free before bringing the stack up:

```bash
ss -ltn | grep -E ':(22|23|1883|5683|1900|8080)\b'
```

## 3. Start the stack

```bash
docker compose up -d --build
```

For a long-running deployment, add the field overlay. It restarts containers on
failure, rotates container logs, caps tarpit CPU and memory, binds the tarpits
on all interfaces, keeps Prometheus/Grafana on localhost, and runs only the
Telnet and MQTT tarpits:

```bash
docker compose -f docker-compose.yml -f docker-compose.field.yml up -d --build
```

`docker-compose.cost.yml` is optional and adds cAdvisor for defender-cost
measurements. It is separate from the core metric path.

## 4. Check it works

```bash
./scripts/smoke.sh
```

This opens one Telnet connection and confirms the exporter counted it. To check
by hand, see the commands in [`README.md`](README.md#checking-it-by-hand).

Grafana and Prometheus stay bound to `127.0.0.1`. Reach them through an SSH
tunnel rather than opening them to the internet:

```bash
ssh -L 3000:127.0.0.1:3000 -L 9090:127.0.0.1:9090 user@your-host
```

## 5. Open the firewall

Only after the stack is verified, allow inbound traffic to the tarpit ports in
your provider's firewall and the host firewall. Never open 3000, 9090, or 9101.

## 6. Update

```bash
git pull
docker compose up -d --build
```

## 7. Stop and clean up

```bash
docker compose down             # stop, keep metric history
docker compose down --volumes   # stop and delete Prometheus/Grafana data
```

Close the firewall ports first if the host stays online.
