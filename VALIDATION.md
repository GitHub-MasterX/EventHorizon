# EventHorizon Validation

## 1. Purpose

This document is the canonical guide for validating EventHorizon's Telnet and
MQTT lifecycle, byte, bounded interaction-depth, persistence, and resource
metrics. The workflow separates deterministic correctness, controlled volume,
deployment wiring, and long-running observation because each provides a
different kind of evidence.

- Exact correctness proves deterministic accounting and parser behavior; it does
  not prove capacity or field behavior.
- Controlled load proves reconciliation and bounded behavior at a known volume;
  it is not an uncontrolled saturation test.
- Remote smoke proves deployment wiring; it is intentionally not a load test.
- Remote controlled load tests a known volume on an authorized field host.
- Public observation tests long-running behavior under unsolicited traffic; it
  does not establish statistical representativeness or production readiness.

## 2. Validation Model

```text
Exact correctness
→ Controlled load
→ Remote smoke
→ Remote controlled load
→ Optional unsolicited observation
```

Advance only after the preceding level passes. A stopped stage is evidence of a
safety control working; it is not a successful higher-volume result.

## 3. Validation Levels

### Level A — Exact correctness

Purpose: exact byte accounting, deterministic lifecycle and interaction depth,
and malformed-event atomicity. Use 1–10 sessions per scenario. The canonical
depth matrix uses four scenarios with 10 sessions each.

### Level B — Local controlled load

Purpose: hundreds and thousands of completed sessions, counter consistency,
resource stability, persistence, and reproducibility. Ramp through 10, 100, and
1,000 total sessions per protocol. The 1,000 sessions are not simultaneous.

### Level C — Remote smoke test

Purpose: prove that the exact commit is deployed, public protocol ports work,
private management ports remain private, and monitoring is connected. It uses
one Telnet and one MQTT session.

> A smoke test is intentionally small and should not be presented as a load test.

### Level D — Remote controlled load

Purpose: validate an authorized field host under bounded deliberate traffic,
compare it with the local validation host, and run 100 then—only when
stable—1,000 total sessions per protocol.

### Level E — Unsolicited public observation

Purpose: observe uncontrolled traffic, long-running stability, real disconnect
behavior, and practical metric usefulness. For an extended observation, use a
reviewed duration such as 48–96 hours and keep all deliberate traffic outside
the observation window.

## 4. Prerequisites

- Linux host with a UTC-synchronized clock and at least 1 GiB of safe free disk.
- Docker and Docker Compose.
- `gcc`, `make`, Go, Bash, Python 3, and `curl`; `jq` and `shellcheck` are useful.
- Prometheus and Grafana from the Compose stack; cAdvisor where the host supports
  it. The runner uses a raw bounded MQTT client, so Mosquitto tools are optional.
- A Linux thermal source such as `/sys/class/thermal/thermal_zone0/temp`, when
  available. Missing temperature or memory-controller support must be reported
  as `UNSUPPORTED`, not treated as zero usage.
- For remote stages: an authorized host, SSH key, exact reviewed commit, public
  TCP 23/1883, and management ports bound only to `127.0.0.1`.

Check ports before starting:

```bash
ss -lntup
docker compose config
```

## 5. Quick Start

Start the local monitoring stack and build tests:

```bash
docker compose -f docker-compose.yml -f docker-compose.cost.yml up -d --build
make test
cd prometheus && go test ./... && go vet ./...
```

Run a small exact matrix:

```bash
./scripts/run_controlled_validation.sh \
  --protocol telnet --profile exact --sessions 4 --concurrency 1 \
  --environment local
```

## 6. Controlled Load Validation

The canonical runner is `scripts/run_controlled_validation.sh`:

```bash
./scripts/run_controlled_validation.sh \
  --protocol telnet --profile mixed --sessions 100 --concurrency 5 \
  --environment local

./scripts/run_controlled_validation.sh \
  --protocol mqtt --profile mixed --sessions 1000 --concurrency 20 \
  --environment local
```

Profiles:

- `exact`: a deterministic four-depth matrix;
- `load`: repeated sessions, depth 2 by default;
- `mixed`: deterministic round-robin distribution across depth 0–3.

Pass `--environment` explicitly so the manifest identifies the validation host
correctly. Use a short, non-sensitive category such as `local`, `ci`, or
`vps`; do not use a hostname or address. The bundled remote-field workflow uses
`vps` to enable its observation-overlap guard.

Default settlement timeout is 60 seconds. Concurrency is capped at 2 for up to
10 sessions, 10 for up to 100, and 25 above 100; total sessions are capped at
10,000. Defaults stop at 80°C, any unexpected restart or OOM, 5% client failure,
1 GiB free disk, persistent lifecycle gap, malformed telemetry growth, or loss
of monitoring. Override thresholds only after reviewing the host.

Every run writes a mode-0700 directory under
`validation-output/controlled/<validation_id>/` containing:

```text
manifest.json
summary.json
summary.md
client-results.csv
prometheus-before.txt
prometheus-after.txt
resource-snapshots.csv
```

The output is ignored by Git. It contains scenario names and bounded counters,
not attacker payloads or public addresses. A run passes only when client,
lifecycle, duration, histogram, depth, malformed-input, restart, OOM, and safety
checks all pass after settlement.

## 7. Interaction Depth Validation

The final metric is:

```text
eventhorizon_session_interaction_depth_total{protocol,depth_level}
```

Both labels are bounded: protocol is `telnet` or `mqtt`; depth is `0` through
`3`. Exactly one classification is emitted for each completed supported session.

| Level | Telnet | MQTT |
| ---: | --- | --- |
| 0 | no meaningful client input | no valid CONNECT |
| 1 | meaningful but incomplete non-empty input | valid CONNECT only |
| 2 | one completed non-empty line | CONNECT plus one PUBLISH, SUBSCRIBE, or UNSUBSCRIBE |
| 3 | continued meaningful interaction after the first line | CONNECT plus two or more meaningful operations |

Telnet CR/LF handling is stream-aware; whitespace-only lines and IAC negotiation
do not advance depth. MQTT PING, QoS acknowledgements, and DISCONNECT do not
advance it. No command, credential, client ID, topic, or payload is retained.
Depth starts at zero, only rises, caps at three, and finalizes once.

Run the deterministic matrices:

```bash
./scripts/run_controlled_validation.sh \
  --protocol telnet --profile exact --sessions 40 --concurrency 2 \
  --environment local

./scripts/run_controlled_validation.sh \
  --protocol mqtt --profile exact --sessions 40 --concurrency 2 \
  --environment local
```

## 8. Persistence Validation

Prometheus uses the `prometheus-data` named volume mounted at `/prometheus` and
Grafana uses `grafana-storage` at `/var/lib/grafana`. Prometheus retention is
explicitly 15 days. Normal `docker compose down` preserves both volumes.

1. Create known traffic and a bounded annotation.
2. Record the UTC start/end and counter value.
3. Record volume names with `docker volume inspect`.
4. Run `docker compose -f docker-compose.yml -f docker-compose.cost.yml down`.
5. Do **not** add `--volumes`.
6. Start the same Compose combination again.
7. Query the original Prometheus timestamp and Grafana annotation API.
8. Generate the exact UTC dashboard URL and inspect it.

`docker compose down --volumes` deletes named volumes and therefore deletes
validation history and Grafana stored state. It is destructive and must never be
part of normal validation.

### How to reopen a previous validation window

```bash
START_UTC="2026-01-15T10:00:00Z"
END_UTC="2026-01-15T10:15:00Z"

./scripts/validation_window_link.sh \
  --dashboard-uid eh-interaction-depth \
  --start "$START_UTC" \
  --end "$END_UTC"
```

The generated URL uses exact epoch milliseconds and `timezone=utc`. Grafana's
provisioned dashboard also provides Last 15 minutes, 1 hour, 6 hours, 24 hours,
3 days, and 7 days quick ranges.

Create a persistent experiment annotation with credentials supplied only through
the process environment:

```bash
GRAFANA_TOKEN="$GRAFANA_TOKEN" ./scripts/validation_annotation.sh start \
  --name "Local MQTT Mixed Load 1000" \
  --environment local --validation-type controlled_load

GRAFANA_TOKEN="$GRAFANA_TOKEN" ./scripts/validation_annotation.sh end \
  --name "Local MQTT Mixed Load 1000" \
  --environment local --validation-type controlled_load
```

Never store Grafana tokens, passwords, or other authentication material in the
repository.

## 9. Remote Validation

Keep these windows distinct:

```text
Window A: deployment and 1+1 remote smoke
Window B: controlled 100-session validation
Window C: controlled 1,000-session validation
Window D: unsolicited public observation
```

The repository provides `scripts/vps_field_*.sh` helpers for an authorized VPS
deployment. Deployment requires a clean reviewed working tree, an explicit
commit, and an exact checkout of that commit on the remote host.

Run external port verification as a separate window before the smoke test:

```bash
./scripts/vps_field_verify_external.sh
./scripts/vps_field_smoke_test.sh --external-verified
```

External verification uses bounded TCP-connect probes and can create protocol
sessions. Let those sessions settle to zero before the smoke test. If the
tarpit intentionally retains a probe connection, perform and record a
controlled stack stop/start without removing volumes. The smoke script refuses
to generate traffic unless both protocol active-client gauges and lifecycle
gaps are zero at its baseline.

Run controlled stages on the remote host itself or through private SSH tunnels
so the runner can reach its loopback-bound Prometheus endpoint. Before using a
non-loopback client target, explicitly set
`EVENTHORIZON_CONTROLLED_TARGET_AUTHORIZED=yes`. Set `--environment vps` in the
runner, annotate and snapshot each window, and never overlap controlled traffic
with Window D.

Only TCP 23 and 1883 are intended to be public for the field scope. Grafana 3000,
Prometheus 9090, exporter 9101, and cAdvisor 8081 must remain on `127.0.0.1`.
Verify from an independent external host.

## 10. Expected Invariants

After settlement, supported Telnet and MQTT runs require exact equality:

```text
final active clients = 0

connections - completed sessions - active sessions = 0

histogram +Inf bucket = histogram count

sum(final interaction-depth levels 0..3) = completed sessions

depth level 0 = early-disconnect classification
```

The current implementation guarantees the last equality. The separate
early-disconnect counter is retained for backward compatibility; depth level 0
is the preferred primitive for new analysis. Counter comparisons must use
before/after deltas from the same exporter process. A restart creates a counter
reset and makes a naive absolute delta inconclusive.

## 11. Output and Evidence

- Runtime evidence: `validation-output/` (ignored, potentially host-specific).
- Committed methodology: `VALIDATION.md`.
- Share summarized evidence deliberately through release notes, issue reports,
  or another project-approved publication channel.

Do not commit TSDB blocks, Grafana databases, Docker volumes, credentials, raw
payloads, source-address lists, or unsummarized scanner output.

## 12. Interpretation

- `PASS`: every stated acceptance check passed with evidence.
- `FAIL`: an expected invariant or safety threshold failed.
- `INCONCLUSIVE`: evidence is missing, boundaries crossed a reset, or the stage
  was not run.
- `UNSUPPORTED`: the host cannot expose a requested feature, such as memory
  accounting; this is not the same as a zero value.
- `INTERIM`: an intentionally running observation has not reached its final end.

Insufficient public traffic is an observation limitation, not a failure. These
tests deliberately do not test saturation or Internet-scale capacity.

## 13. Troubleshooting

- **Ports occupied:** inspect `ss -lntup` and Compose mappings; do not kill an
  unrelated service automatically.
- **cgroup memory unavailable / `0B / 0B`:** check
  `/sys/fs/cgroup/cgroup.controllers`; report `UNSUPPORTED` and use a supported
  host for the missing measurement.
- **Active clients do not settle:** stop the next ramp, inspect container logs and
  lifecycle gap, and retain the failed run directory.
- **Prometheus counter reset:** split the window at the restart; do not add values
  across it as if they were one process.
- **Missing series:** wait for two scrapes, check exporter `/metrics`, target
  health, spelling, and bounded label values.
- **MQTT client unavailable:** the canonical Python runner needs no external MQTT
  package; Mosquitto clients are optional for manual smoke tests.
- **Grafana history missing:** verify named volume mounts and Prometheus retention.
  If `down --volumes` was used, recovery requires an external backup; EventHorizon
  does not create one automatically.
- **High host temperature:** stop/pause the ramp at the configured threshold, cool
  the host, and restart at the last passing stage.
- **Container restart/OOM:** stop the ramp, retain evidence, inspect state/logs,
  and do not call the run a pass.

## 14. Safety

Use the 10 → 100 → 1,000 progressive ramp with bounded concurrency. Never scan
broad address ranges. Send deliberate traffic only to the local validation host
or a specifically authorized remote host, keep management ports private, and
verify target authorization before any non-loopback run. Stop on unexpected
restart/OOM, persistent lifecycle gap, malformed telemetry growth, excessive
failure rate or temperature, unsafe disk space, or loss of monitoring. This
workflow does not authorize destructive firewall changes, uncontrolled
saturation, or millions of concurrent sessions.
