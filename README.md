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



## 🚀 How to Run

### 1️⃣ Start all services
The programs are run using Docker.  
To start all components, simply run:

```bash
docker compose up
```

## Validation

Use [`VALIDATION.md`](VALIDATION.md) as the canonical guide for exact tests, controlled volume validation, persistent monitoring, authorized VPS stages, and historical Grafana experiment windows.

### Supported exact-commit VPS workflow

The Week 10 deployment topology is one Linux operator workstation with Git,
GitHub CLI, SSH, Bash-compatible tooling, Python 3.10+, and repository access,
plus one authorized Linux VPS with Docker Compose. Raspberry Pi remains a
validated test environment; it is not required for deployment.

First prove that the full trusted-upstream SHA has the required successful push
workflow:

```bash
DEPLOY_COMMIT=<full-40-character-sha>
./scripts/vps_field_deploy.sh --check-only --commit "$DEPLOY_COMMIT"
```

Copy `deploy/vps-field.env.example` to the ignored operator configuration,
populate only its documented keys, and restrict it to the operator:

```bash
cp deploy/vps-field.env.example deploy/vps-field.env
chmod 0600 deploy/vps-field.env
```

After reviewing target authorization and firewall policy, deploy the same SHA
from an interactive terminal:

```bash
./scripts/vps_field_deploy.sh \
  --commit "$DEPLOY_COMMIT" \
  --env-file deploy/vps-field.env
```

The command performs the documented preflight, exact-source deployment,
runtime and port checks, deterministic Telnet/MQTT smoke, and final allowlisted
evidence retrieval. A successful run reports `PASS` with highest proven state
`ENVIRONMENT_VALIDATED` and leaves the six field services running in restricted
validation posture. Evidence is retained under
`validation-output/deployments/<run-id>/`; target values, credentials, raw
traffic, source addresses, and unrestricted logs are excluded.
