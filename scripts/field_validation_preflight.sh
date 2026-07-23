#!/usr/bin/env bash
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
FIELD_PROJECT_NAME="${FIELD_PROJECT_NAME:-eventhorizon-field}"
LOCAL_SMOKE=false
FAILURES=0

if [[ "${1:-}" == "--local-smoke" ]]; then
    LOCAL_SMOKE=true
elif [[ $# -gt 0 ]]; then
    echo "Usage: $0 [--local-smoke]" >&2
    exit 2
fi

pass() { printf 'PASS: %s\n' "$*"; }
warn() { printf 'WARN: %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; FAILURES=$((FAILURES + 1)); }

cd "$REPO_ROOT" || exit 1
printf 'EventHorizon field-validation preflight\n'
printf 'UTC time: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf 'Project: %s\n' "$FIELD_PROJECT_NAME"

if $LOCAL_SMOKE; then
    warn "local smoke mode does not authorize or start a public deployment"
elif [[ "${EVENTHORIZON_FIELD_AUTHORIZED:-}" == "yes" ]]; then
    pass "operator explicitly confirmed an authorized field environment"
else
    fail "set EVENTHORIZON_FIELD_AUTHORIZED=yes only after authorization, host, interface, and firewall policy are confirmed"
fi

branch="$(git branch --show-current 2>/dev/null || true)"
if [[ "$branch" == "GSoC_2026" ]]; then
    pass "Git branch is GSoC_2026"
else
    fail "Git branch is '$branch', expected GSoC_2026"
fi
printf 'Commit: %s\n' "$(git rev-parse HEAD 2>/dev/null || printf unknown)"
if [[ -n "$(git status --short 2>/dev/null)" ]]; then
    warn "worktree is dirty; record and review the exact diff before deployment"
else
    pass "worktree is clean"
fi

for command_name in docker curl python3 ss; do
    if command -v "$command_name" >/dev/null 2>&1; then
        pass "$command_name is available"
    else
        fail "$command_name is required"
    fi
done

if ! docker compose version >/dev/null 2>&1; then
    fail "Docker Compose is unavailable"
else
    pass "$(docker compose version)"
fi

compose_yaml="$(mktemp)"
compose_json="$(mktemp)"
cleanup() {
    rm -f "$compose_yaml" "$compose_json"
}
trap cleanup EXIT

COMPOSE=(docker compose -p "$FIELD_PROJECT_NAME" -f docker-compose.yml -f docker-compose.cost.yml -f docker-compose.field.yml)
if "${COMPOSE[@]}" config >"$compose_yaml" && "${COMPOSE[@]}" config --format json >"$compose_json"; then
    pass "field Compose configuration resolves"
else
    fail "field Compose configuration is invalid"
fi

if [[ -s "$compose_json" ]] && python3 - "$compose_json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    config = json.load(source)

services = config.get("services", {})
expected = {"telnet_pit", "mqtt_pit", "prometheus-exporter", "prometheus", "grafana", "cadvisor"}
if set(services) != expected:
    raise SystemExit(f"active services are {sorted(services)}, expected {sorted(expected)}")

public = {"telnet_pit": ("23", 23), "mqtt_pit": ("1883", 1883)}
private = {
    "prometheus-exporter": ("9101", 9101),
    "prometheus": ("9090", 9090),
    "grafana": ("3000", 3000),
    "cadvisor": ("8081", 8080),
}

for service, (published, target) in public.items():
    ports = services[service].get("ports", [])
    if len(ports) != 1:
        raise SystemExit(f"{service} must publish exactly one port")
    port = ports[0]
    if (port.get("host_ip"), str(port.get("published")), port.get("target"), port.get("protocol")) != ("0.0.0.0", published, target, "tcp"):
        raise SystemExit(f"unsafe or unexpected {service} port mapping: {port}")

for service, (published, target) in private.items():
    ports = services[service].get("ports", [])
    if len(ports) != 1:
        raise SystemExit(f"{service} must publish exactly one management port")
    port = ports[0]
    if (port.get("host_ip"), str(port.get("published")), port.get("target"), port.get("protocol")) != ("127.0.0.1", published, target, "tcp"):
        raise SystemExit(f"public or unexpected {service} management mapping: {port}")

exporter_environment = services["prometheus-exporter"].get("environment", {})
if exporter_environment.get("EVENTHORIZON_FIELD_SAFE_MODE") != "true":
    raise SystemExit("exporter field-safe mode is not enabled")

def require_named_mount(service_name, source, target):
    matches = [
        mount for mount in services[service_name].get("volumes", [])
        if mount.get("type") == "volume"
        and mount.get("source") == source
        and mount.get("target") == target
    ]
    if len(matches) != 1:
        raise SystemExit(
            f"{service_name} must mount named volume {source!r} exactly once at {target!r}"
        )

require_named_mount("prometheus", "prometheus-data", "/prometheus")
require_named_mount("grafana", "grafana-storage", "/var/lib/grafana")
declared_volumes = config.get("volumes", {})
if not {"prometheus-data", "grafana-storage"}.issubset(declared_volumes):
    raise SystemExit("Prometheus and Grafana named volumes are not declared")

prometheus_command = services["prometheus"].get("command", [])
required_flags = {
    "--storage.tsdb.path=/prometheus",
    "--storage.tsdb.retention.time=15d",
}
if not required_flags.issubset(prometheus_command):
    raise SystemExit("Prometheus persistent path or explicit 15-day retention is missing")

for service in ("telnet_pit", "mqtt_pit"):
    if services[service].get("logging", {}).get("driver") != "none":
        raise SystemExit(f"{service} may persist raw client content in container logs")
    if services[service].get("environment", {}).get("EVENTHORIZON_SESSION_LOG") != "/dev/null":
        raise SystemExit(f"{service} session log is not disabled for aggregate-only field validation")

print("bindings, persistence, retention, field-safe metrics, and raw-log suppression are valid")
PY
then
    pass "public/private bindings, persistent monitoring, retention, and raw-log suppression are valid"
else
    fail "field Compose safety policy validation failed"
fi

if command -v jq >/dev/null 2>&1; then
    if find grafana -name '*.json' -print0 | xargs -0 -r -n1 jq empty; then
        pass "Grafana JSON is valid (jq)"
    else
        fail "Grafana JSON validation failed"
    fi
else
    warn "jq is unavailable; using the documented Python JSON fallback"
    if python3 - <<'PY'
import json
from pathlib import Path

for path in Path("grafana").rglob("*.json"):
    with path.open(encoding="utf-8") as source:
        json.load(source)
PY
    then
        pass "Grafana JSON is valid (Python fallback)"
    else
        fail "Grafana JSON validation failed"
    fi
fi

if command -v promtool >/dev/null 2>&1; then
    if promtool check config prometheus/prometheus.cost.yml >/dev/null; then
        pass "Prometheus cost configuration is valid (local promtool)"
    else
        fail "Prometheus cost configuration failed promtool validation"
    fi
elif docker image inspect prom/prometheus >/dev/null 2>&1; then
    if docker run --rm --entrypoint promtool \
        -v "$REPO_ROOT/prometheus:/etc/eventhorizon-prometheus:ro" prom/prometheus \
        check config /etc/eventhorizon-prometheus/prometheus.cost.yml >/dev/null; then
        pass "Prometheus cost configuration is valid (containerized promtool)"
    else
        fail "Prometheus cost configuration failed containerized promtool validation"
    fi
else
    fail "promtool is unavailable and the Prometheus image is not present; do not pull implicitly during preflight"
fi

available_kib="$(df -Pk "$REPO_ROOT" | awk 'NR==2 {print $4}')"
if [[ "$available_kib" =~ ^[0-9]+$ ]] && ((available_kib >= 2097152)); then
    pass "at least 2 GiB of disk space is available"
elif [[ "$available_kib" =~ ^[0-9]+$ ]] && ((available_kib >= 1048576)); then
    warn "less than 2 GiB of disk space is available"
else
    fail "less than 1 GiB of disk space is available"
fi

memory_supported=false
if [[ -r /sys/fs/cgroup/cgroup.controllers ]] && grep -qw memory /sys/fs/cgroup/cgroup.controllers && [[ -r /sys/fs/cgroup/memory.current ]]; then
    memory_supported=true
fi
if $memory_supported; then
    pass "cgroup-v2 memory accounting is available"
    if [[ -z "${FIELD_TARPIT_MEMORY_LIMIT:-}" || "${FIELD_TARPIT_MEMORY_LIMIT}" == "0" ]]; then
        fail "set FIELD_TARPIT_MEMORY_LIMIT (for example 256m) on this memory-capable host"
    else
        pass "field tarpit memory limit is ${FIELD_TARPIT_MEMORY_LIMIT}"
    fi
else
    warn "cgroup-v2 memory accounting is unavailable; memory results and limits must be marked unsupported"
    if [[ -n "${FIELD_TARPIT_MEMORY_LIMIT:-}" && "${FIELD_TARPIT_MEMORY_LIMIT}" != "0" ]]; then
        fail "a memory limit was requested on a host that cannot account for it reliably"
    fi
fi

for port in 23 1883 9101 9090 3000 8081; do
    if command -v ss >/dev/null 2>&1 && ss -H -ltn | awk '{print $4}' | grep -Eq "(^|:|\\])${port}$"; then
        if $LOCAL_SMOKE; then
            warn "TCP port $port is already listening (allowed only for inspection of the existing local smoke stack)"
        else
            fail "TCP port $port is already in use; resolve the conflict before field deployment"
        fi
    else
        pass "TCP port $port is available"
    fi
done

if docker info >/dev/null 2>&1; then
    pass "Docker daemon is reachable"
    for fixed_name in prometheus-exporter prometheus grafana cadvisor; do
        if existing_project="$(docker inspect --format '{{index .Config.Labels "com.docker.compose.project"}}' "$fixed_name" 2>/dev/null)"; then
            if [[ "$existing_project" != "$FIELD_PROJECT_NAME" ]]; then
                if $LOCAL_SMOKE; then
                    warn "container name $fixed_name belongs to existing project $existing_project"
                else
                    fail "container name $fixed_name belongs to project $existing_project; stop or isolate the development stack first"
                fi
            fi
        fi
    done
    running_ids="$("${COMPOSE[@]}" ps -q 2>/dev/null || true)"
    if [[ -z "$running_ids" ]]; then
        pass "field project is not already running"
    else
        unhealthy="$(docker inspect --format '{{.Name}} {{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{else}}no-healthcheck{{end}} {{.RestartCount}}' $running_ids 2>/dev/null | grep -Ev ' running (healthy|no-healthcheck) 0$' || true)"
        if [[ -n "$unhealthy" ]]; then
            fail "field project has unhealthy, stopped, or restarted containers: $unhealthy"
        else
            pass "running field containers are healthy with zero restarts"
        fi
    fi
else
    fail "Docker daemon is not reachable"
fi

if ((FAILURES > 0)); then
    printf 'Preflight blocked deployment with %d critical failure(s).\n' "$FAILURES" >&2
    exit 1
fi

printf 'Preflight passed. This script does not change firewall rules or start containers.\n'
