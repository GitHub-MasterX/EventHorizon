#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/vps_field_common.sh
source "$SCRIPT_DIR/vps_field_common.sh"
vps_field_load_env

usage() {
    printf 'Usage: %s --external-verified\n' "$0"
}

case "${1:-}" in
    --external-verified)
        [[ $# -eq 1 ]] || vps_field_die "usage: $0 --external-verified"
        ;;
    --help|-h)
        usage
        exit 0
        ;;
    *)
        usage >&2
        vps_field_die "run scripts/vps_field_verify_external.sh as a separate window, then pass --external-verified"
        ;;
esac

vps_field_require_clean_commit

for process_name in mosquitto_pub nc nmap masscan zmap; do
    if pgrep -x "$process_name" >/dev/null 2>&1; then
        vps_field_die "controlled traffic process '$process_name' is still running locally"
    fi
done

python3 - "$VPS_FIELD_REPO_ROOT/validation-output/annotations" <<'PY'
import json
import sys
from pathlib import Path

state_dir = Path(sys.argv[1])
if state_dir.is_dir():
    running = []
    for state_path in state_dir.glob("*.json"):
        state = json.loads(state_path.read_text(encoding="utf-8"))
        if state.get("status") == "running":
            running.append(state.get("name", state_path.name))
    if running:
        raise SystemExit(
            "validation annotations are still running: " + ", ".join(sorted(running))
        )
PY

printf 'External port verification already completed in a separate window.\n'
baseline_snapshot="$("$SCRIPT_DIR/vps_field_snapshot_remote.sh" --once)"

vps_field_ssh bash -s -- \
    "$VPS_DEPLOY_DIR" \
    "$VPS_PROJECT_NAME" \
    "$DEPLOY_COMMIT" \
    "$FIELD_DURATION_HOURS" \
    "$baseline_snapshot" <<'REMOTE'
set -euo pipefail
deploy_dir_input="$1"
project_name="$2"
expected_commit="$3"
duration_hours="$4"
baseline_snapshot="$5"
case "$deploy_dir_input" in
    "~/"*) deploy_dir="$HOME/${deploy_dir_input#\~/}" ;;
    /*) deploy_dir="$deploy_dir_input" ;;
    *) exit 1 ;;
esac
cd "$deploy_dir"
[[ "$(git rev-parse HEAD)" == "$expected_commit" ]]

python3 - <<'PY'
import json
from pathlib import Path

result_path = Path("validation-output/smoke/smoke_result.json")
if not result_path.is_file():
    raise SystemExit("controlled VPS smoke result is missing")
result = json.loads(result_path.read_text(encoding="utf-8"))
if result.get("status") != "pass":
    raise SystemExit("controlled VPS smoke test did not pass")
PY

compose=(docker compose -p "$project_name" -f docker-compose.yml -f docker-compose.cost.yml -f docker-compose.field.yml)
for service in prometheus-exporter telnet_pit mqtt_pit prometheus grafana cadvisor; do
    container_id="$("${compose[@]}" ps -q "$service")"
    [[ -n "$container_id" ]]
    [[ "$(docker inspect --format '{{.State.Status}}' "$container_id")" == running ]]
    health="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}not-configured{{end}}' "$container_id")"
    [[ "$health" != unhealthy && "$health" != starting ]]
    [[ "$(docker inspect --format '{{.RestartCount}}' "$container_id")" == 0 ]]
    [[ "$(docker inspect --format '{{.State.OOMKilled}}' "$container_id")" == false ]]
done

if pgrep -x mosquitto_pub >/dev/null 2>&1 || pgrep -x nc >/dev/null 2>&1 || pgrep -x nmap >/dev/null 2>&1 || \
   pgrep -x masscan >/dev/null 2>&1 || pgrep -x zmap >/dev/null 2>&1; then
    printf 'A traffic-generation or scanning process is running on the VPS.\n' >&2
    exit 1
fi

python3 - <<'PY'
import json
import urllib.parse
import urllib.request

queries = {
    "telnet active clients": 'sum(current_connected_clients{server="Telnet"}) or vector(0)',
    "mqtt active clients": 'sum(current_connected_clients{server="MQTT"}) or vector(0)',
    "telnet lifecycle gap": (
        'sum(total_connects{server="Telnet"}) '
        '- sum(eventhorizon_completed_sessions_total{protocol="telnet"}) '
        '- sum(current_connected_clients{server="Telnet"})'
    ),
    "mqtt lifecycle gap": (
        'sum(total_connects{server="MQTT"}) '
        '- sum(eventhorizon_completed_sessions_total{protocol="mqtt"}) '
        '- sum(current_connected_clients{server="MQTT"})'
    ),
    "telnet depth gap": (
        'sum(eventhorizon_completed_sessions_total{protocol="telnet"}) '
        '- sum(eventhorizon_session_interaction_depth_total{protocol="telnet"})'
    ),
    "mqtt depth gap": (
        'sum(eventhorizon_completed_sessions_total{protocol="mqtt"}) '
        '- sum(eventhorizon_session_interaction_depth_total{protocol="mqtt"})'
    ),
}

failures = []
for name, expression in queries.items():
    encoded = urllib.parse.urlencode({"query": expression})
    with urllib.request.urlopen(
        f"http://127.0.0.1:9090/api/v1/query?{encoded}", timeout=10
    ) as response:
        payload = json.load(response)
    if payload.get("status") != "success" or len(payload["data"]["result"]) != 1:
        raise SystemExit(f"unexpected Prometheus response for {name}: {payload!r}")
    value = float(payload["data"]["result"][0]["value"][1])
    if value != 0:
        failures.append(f"{name}={value:g}, expected 0")

if failures:
    raise SystemExit(
        "pre-observation baseline is not clean; observation was not started: "
        + "; ".join(failures)
    )
PY

export OBSERVATION_DURATION_HOURS="$duration_hours"
export OBSERVATION_COMMIT="$expected_commit"
export OBSERVATION_BASELINE="$baseline_snapshot"
python3 - <<'PY'
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

output = Path("validation-output/observation_window.json")
if output.exists():
    current = json.loads(output.read_text(encoding="utf-8"))
    if current.get("status") == "running":
        raise SystemExit("an observation window is already recorded as running")

start = datetime.now(timezone.utc)
duration = int(os.environ["OBSERVATION_DURATION_HOURS"])
document = {
    "status": "running",
    "start_utc": start.isoformat().replace("+00:00", "Z"),
    "planned_end_utc": (start + timedelta(hours=duration)).isoformat().replace("+00:00", "Z"),
    "duration_hours": duration,
    "commit": os.environ["OBSERVATION_COMMIT"],
    "public_ports": ["23/tcp", "1883/tcp"],
    "baseline_snapshot_location": os.environ["OBSERVATION_BASELINE"],
    "traffic_policy": "unsolicited only; no deliberate scanner or controlled client traffic",
}
output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
output.chmod(0o600)
print(json.dumps(document, indent=2, sort_keys=True))
PY
REMOTE

printf '\nUnsolicited observation window recorded. Do not generate controlled traffic during this window.\n'
printf 'Open TCP 23 and 1883 according to the approved public provider policy now; keep management ports private.\n'
printf 'Manual status snapshot:\n  %s/scripts/vps_field_snapshot_remote.sh\n' "$VPS_FIELD_REPO_ROOT"
printf 'Background local snapshot loop:\n  %s/scripts/vps_field_snapshot_remote.sh --loop\n' "$VPS_FIELD_REPO_ROOT"
printf 'Stop and retrieve evidence:\n  %s/scripts/vps_field_stop_remote.sh\n' "$VPS_FIELD_REPO_ROOT"
