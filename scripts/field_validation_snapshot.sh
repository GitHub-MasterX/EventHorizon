#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
FIELD_PROJECT_NAME="${FIELD_PROJECT_NAME:-eventhorizon-field}"
PROMETHEUS_URL="${PROMETHEUS_URL:-http://127.0.0.1:9090}"
OUTPUT_DIR="${FIELD_VALIDATION_OUTPUT_DIR:-$REPO_ROOT/validation-output}"
UTC_STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUTPUT_FILE="$OUTPUT_DIR/field-snapshot-$UTC_STAMP.txt"
umask 077
mkdir -p "$OUTPUT_DIR"

cd "$REPO_ROOT"
COMPOSE=(docker compose -p "$FIELD_PROJECT_NAME" -f docker-compose.yml -f docker-compose.cost.yml -f docker-compose.field.yml)

prom_query() {
    local title="$1"
    local query="$2"
    printf '\n[%s]\nquery: %s\n' "$title" "$query"
    if ! curl --fail --silent --show-error --get --data-urlencode "query=$query" "$PROMETHEUS_URL/api/v1/query" |
        python3 -c '
import json, sys
payload = json.load(sys.stdin)
if payload.get("status") != "success":
    raise SystemExit(payload)
results = payload.get("data", {}).get("result", [])
if not results:
    print("NO_DATA")
for item in results:
    labels = ",".join(f"{key}={value}" for key, value in sorted(item.get("metric", {}).items()) if key != "__name__")
    value = item.get("value", [None, "NO_VALUE"])[1]
    display = labels or "aggregate"
    print(f"{display} {value}")
'; then
        printf 'QUERY_FAILED\n'
    fi
}

{
    printf 'EventHorizon field-validation aggregate snapshot\n'
    printf 'utc_timestamp=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'commit=%s\n' "$(git rev-parse HEAD)"
    printf 'branch=%s\n' "$(git branch --show-current)"
    printf 'project=%s\n' "$FIELD_PROJECT_NAME"
    printf 'architecture=%s\n' "$(uname -m)"
    printf 'kernel=%s\n' "$(uname -r)"
    printf 'prometheus_scrape_interval=15s\n'
    if [[ -r /sys/fs/cgroup/cgroup.controllers ]] && grep -qw memory /sys/fs/cgroup/cgroup.controllers && [[ -r /sys/fs/cgroup/memory.current ]]; then
        printf 'cgroup_v2_memory_accounting=supported\n'
    else
        printf 'cgroup_v2_memory_accounting=unsupported\n'
    fi

    printf '\n[compose state]\n'
    "${COMPOSE[@]}" ps -a || true

    mapfile -t container_ids < <("${COMPOSE[@]}" ps -aq 2>/dev/null || true)
    if ((${#container_ids[@]} > 0)); then
        printf '\n[restart, health, and OOM evidence]\n'
        for container_id in "${container_ids[@]}"; do
            docker inspect --format '{{.Name}} status={{.State.Status}} health={{if .State.Health}}{{.State.Health.Status}}{{else}}not-configured{{end}} restarts={{.RestartCount}} oom_killed={{.State.OOMKilled}} exit_code={{.State.ExitCode}}' "$container_id" | sed 's#^/##'
        done
    else
        printf '\n[restart, health, and OOM evidence]\nNO_FIELD_CONTAINERS\n'
    fi

    mapfile -t tarpit_ids < <("${COMPOSE[@]}" ps -q telnet_pit mqtt_pit 2>/dev/null || true)
    printf '\n[instantaneous container stats]\n'
    if ((${#tarpit_ids[@]} > 0)); then
        docker stats --no-stream --format '{{.Name}} cpu={{.CPUPerc}} memory={{.MemUsage}} network={{.NetIO}} pids={{.PIDs}}' "${tarpit_ids[@]}"
    else
        printf 'NO_RUNNING_TARPITS\n'
    fi

    prom_query "connections" 'sum by (server) (total_connects{server=~"Telnet|MQTT"})'
    prom_query "completed sessions" 'sum by (protocol) (eventhorizon_completed_sessions_total{protocol=~"telnet|mqtt"})'
    prom_query "active clients" 'sum by (server) (current_connected_clients{server=~"Telnet|MQTT"})'
    prom_query "Telnet lifecycle gap" 'sum(total_connects{server="Telnet"}) - sum(eventhorizon_completed_sessions_total{protocol="telnet"}) - sum(current_connected_clients{server="Telnet"})'
    prom_query "MQTT lifecycle gap" 'sum(total_connects{server="MQTT"}) - sum(eventhorizon_completed_sessions_total{protocol="mqtt"}) - sum(current_connected_clients{server="MQTT"})'
    prom_query "histogram +Inf minus count" 'sum by (protocol) (eventhorizon_session_duration_ms_bucket{protocol=~"telnet|mqtt",le="+Inf"}) - sum by (protocol) (eventhorizon_session_duration_ms_count{protocol=~"telnet|mqtt"})'
    prom_query "disconnect reasons" 'sum by (protocol, disconnect_reason) (eventhorizon_completed_sessions_total{protocol=~"telnet|mqtt"})'
    prom_query "bounded protocol actions" 'sum by (protocol, action) (eventhorizon_protocol_actions_total{protocol=~"telnet|mqtt"})'
    prom_query "early disconnect" 'sum by (protocol) (eventhorizon_early_disconnect_total{protocol=~"telnet|mqtt"})'
    prom_query "application bytes received" 'sum by (protocol) (eventhorizon_bytes_received_total{protocol=~"telnet|mqtt"})'
    prom_query "application bytes sent" 'sum by (protocol) (eventhorizon_bytes_sent_total{protocol=~"telnet|mqtt"})'
    prom_query "malformed exporter messages" 'sum by (reason) (eventhorizon_exporter_malformed_messages_total)'
    prom_query "read outcomes" 'sum by (protocol, reason) (eventhorizon_read_errors_total{protocol=~"telnet|mqtt"})'
    prom_query "write outcomes" 'sum by (protocol, reason) (eventhorizon_write_errors_total{protocol=~"telnet|mqtt"})'
    prom_query "five-minute tarpit CPU cores" 'sum by (container_label_com_docker_compose_service) (rate(container_cpu_usage_seconds_total{container_label_com_docker_compose_service=~"telnet_pit|mqtt_pit"}[5m]))'
    prom_query "tarpit memory working set" 'sum by (container_label_com_docker_compose_service) (container_memory_working_set_bytes{container_label_com_docker_compose_service=~"telnet_pit|mqtt_pit"})'
    prom_query "five-minute container network receive" 'sum by (container_label_com_docker_compose_service) (rate(container_network_receive_bytes_total{container_label_com_docker_compose_service=~"telnet_pit|mqtt_pit"}[5m]))'
    prom_query "five-minute container network transmit" 'sum by (container_label_com_docker_compose_service) (rate(container_network_transmit_bytes_total{container_label_com_docker_compose_service=~"telnet_pit|mqtt_pit"}[5m]))'
} >"$OUTPUT_FILE"

printf '%s\n' "$OUTPUT_FILE"
