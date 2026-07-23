#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/vps_field_common.sh
source "$SCRIPT_DIR/vps_field_common.sh"
vps_field_load_env

command -v nc >/dev/null 2>&1 || vps_field_die "nc is required for the controlled Telnet interaction"
command -v mosquitto_pub >/dev/null 2>&1 || vps_field_die "mosquitto_pub is required for the controlled MQTT interaction"
command -v timeout >/dev/null 2>&1 || vps_field_die "timeout is required for bounded client execution"

"$SCRIPT_DIR/vps_field_verify_external.sh"

printf '\nControlled VPS smoke test\n'
printf 'Before continuing, TCP 23 and 1883 should be temporarily restricted by the reviewed firewall policy to ADMIN_SOURCE_CIDR=%s.\n' "$ADMIN_SOURCE_CIDR"
if [[ ! -t 0 ]]; then
    vps_field_die "smoke-test confirmation requires an interactive terminal"
fi
read -r -p 'Type SMOKE after confirming the restricted controlled window: ' confirmation
[[ "$confirmation" == SMOKE ]] || vps_field_die "smoke test cancelled"

capture_metrics() {
    local phase="$1"
    vps_field_ssh bash -s -- "$VPS_DEPLOY_DIR" "$VPS_PROJECT_NAME" "$DEPLOY_COMMIT" "$phase" <<'REMOTE'
set -euo pipefail
deploy_dir_input="$1"
project_name="$2"
expected_commit="$3"
phase="$4"
case "$deploy_dir_input" in
    "~/"*) deploy_dir="$HOME/${deploy_dir_input#\~/}" ;;
    /*) deploy_dir="$deploy_dir_input" ;;
    *) exit 1 ;;
esac
cd "$deploy_dir"
[[ "$(git rev-parse HEAD)" == "$expected_commit" ]]
compose=(docker compose -p "$project_name" -f docker-compose.yml -f docker-compose.cost.yml -f docker-compose.field.yml)
for service in prometheus-exporter telnet_pit mqtt_pit prometheus grafana cadvisor; do
    container_id="$("${compose[@]}" ps -q "$service")"
    [[ -n "$container_id" ]]
    [[ "$(docker inspect --format '{{.State.Status}}' "$container_id")" == running ]]
done
mkdir -p validation-output/smoke
chmod 700 validation-output validation-output/smoke
SMOKE_PHASE="$phase" python3 - <<'PY'
import json
import os
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

queries = {
    "telnet_connections": 'sum(total_connects{server="Telnet"}) or vector(0)',
    "mqtt_connections": 'sum(total_connects{server="MQTT"}) or vector(0)',
    "telnet_completions": 'sum(eventhorizon_completed_sessions_total{protocol="telnet"}) or vector(0)',
    "mqtt_completions": 'sum(eventhorizon_completed_sessions_total{protocol="mqtt"}) or vector(0)',
    "telnet_active": 'sum(current_connected_clients{server="Telnet"}) or vector(0)',
    "mqtt_active": 'sum(current_connected_clients{server="MQTT"}) or vector(0)',
    "telnet_duration_count": 'sum(eventhorizon_session_duration_ms_count{protocol="telnet"}) or vector(0)',
    "mqtt_duration_count": 'sum(eventhorizon_session_duration_ms_count{protocol="mqtt"}) or vector(0)',
    "telnet_duration_inf": 'sum(eventhorizon_session_duration_ms_bucket{protocol="telnet",le="+Inf"}) or vector(0)',
    "mqtt_duration_inf": 'sum(eventhorizon_session_duration_ms_bucket{protocol="mqtt",le="+Inf"}) or vector(0)',
    "telnet_rx_bytes": 'sum(eventhorizon_bytes_received_total{protocol="telnet"}) or vector(0)',
    "mqtt_rx_bytes": 'sum(eventhorizon_bytes_received_total{protocol="mqtt"}) or vector(0)',
    "telnet_tx_bytes": 'sum(eventhorizon_bytes_sent_total{protocol="telnet"}) or vector(0)',
    "mqtt_tx_bytes": 'sum(eventhorizon_bytes_sent_total{protocol="mqtt"}) or vector(0)',
    "telnet_depth_total": 'sum(eventhorizon_session_interaction_depth_total{protocol="telnet"}) or vector(0)',
    "mqtt_depth_total": 'sum(eventhorizon_session_interaction_depth_total{protocol="mqtt"}) or vector(0)',
    "telnet_depth_0": 'sum(eventhorizon_session_interaction_depth_total{protocol="telnet",depth_level="0"}) or vector(0)',
    "mqtt_depth_0": 'sum(eventhorizon_session_interaction_depth_total{protocol="mqtt",depth_level="0"}) or vector(0)',
    "telnet_depth_2": 'sum(eventhorizon_session_interaction_depth_total{protocol="telnet",depth_level="2"}) or vector(0)',
    "mqtt_depth_2": 'sum(eventhorizon_session_interaction_depth_total{protocol="mqtt",depth_level="2"}) or vector(0)',
    "telnet_early_disconnect": 'sum(eventhorizon_early_disconnect_total{protocol="telnet"}) or vector(0)',
    "mqtt_early_disconnect": 'sum(eventhorizon_early_disconnect_total{protocol="mqtt"}) or vector(0)',
    "malformed": 'sum(eventhorizon_exporter_malformed_messages_total) or vector(0)',
    "read_outcomes": 'sum(eventhorizon_read_errors_total{protocol=~"telnet|mqtt"}) or vector(0)',
    "write_outcomes": 'sum(eventhorizon_write_errors_total{protocol=~"telnet|mqtt"}) or vector(0)',
}

def query(expression):
    encoded = urllib.parse.urlencode({"query": expression})
    with urllib.request.urlopen(f"http://127.0.0.1:9090/api/v1/query?{encoded}", timeout=10) as response:
        payload = json.load(response)
    if payload.get("status") != "success" or len(payload["data"]["result"]) != 1:
        raise RuntimeError(f"unexpected Prometheus response for {expression!r}: {payload!r}")
    return float(payload["data"]["result"][0]["value"][1])

document = {
    "label": "Controlled VPS smoke test",
    "phase": os.environ["SMOKE_PHASE"],
    "captured_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "metrics": {name: query(expression) for name, expression in queries.items()},
}
output = Path(f"validation-output/smoke/{os.environ['SMOKE_PHASE']}.json")
output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
output.chmod(0o600)
print(output)
PY
REMOTE
}

smoke_start_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
capture_metrics before

set +e
printf 'vps-field-smoke\n' | timeout 8 nc -q 1 -w 5 "$VPS_HOST" 23 >/dev/null
telnet_status=$?
set -e
if ((telnet_status != 0 && telnet_status != 124)); then
    vps_field_die "controlled Telnet client failed with status $telnet_status"
fi

timeout 12 mosquitto_pub \
    -h "$VPS_HOST" \
    -p 1883 \
    -V mqttv311 \
    -i gsoc-vps-field-smoke \
    -t gsoc/vps-field-smoke \
    -m known-smoke-payload \
    -q 0

# One 15-second Prometheus scrape plus margin.
sleep 25
capture_metrics after
smoke_end_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

vps_field_ssh bash -s -- "$VPS_DEPLOY_DIR" "$DEPLOY_COMMIT" "$smoke_start_utc" "$smoke_end_utc" <<'REMOTE'
set -euo pipefail
deploy_dir_input="$1"
expected_commit="$2"
start_utc="$3"
end_utc="$4"
case "$deploy_dir_input" in
    "~/"*) deploy_dir="$HOME/${deploy_dir_input#\~/}" ;;
    /*) deploy_dir="$deploy_dir_input" ;;
    *) exit 1 ;;
esac
cd "$deploy_dir"
[[ "$(git rev-parse HEAD)" == "$expected_commit" ]]
SMOKE_START_UTC="$start_utc" SMOKE_END_UTC="$end_utc" python3 - <<'PY'
import json
import os
from pathlib import Path

directory = Path("validation-output/smoke")
before = json.loads((directory / "before.json").read_text(encoding="utf-8"))["metrics"]
after = json.loads((directory / "after.json").read_text(encoding="utf-8"))["metrics"]
deltas = {name: after[name] - before[name] for name in before}
checks = {}

for protocol in ("telnet", "mqtt"):
    checks[f"{protocol}_connections_plus_one"] = deltas[f"{protocol}_connections"] == 1
    checks[f"{protocol}_completions_plus_one"] = deltas[f"{protocol}_completions"] == 1
    checks[f"{protocol}_active_settled"] = after[f"{protocol}_active"] == 0
    checks[f"{protocol}_duration_plus_one"] = deltas[f"{protocol}_duration_count"] == 1
    checks[f"{protocol}_histogram_consistent"] = after[f"{protocol}_duration_inf"] == after[f"{protocol}_duration_count"]
    checks[f"{protocol}_rx_increased"] = deltas[f"{protocol}_rx_bytes"] > 0
    checks[f"{protocol}_tx_increased"] = deltas[f"{protocol}_tx_bytes"] > 0
    checks[f"{protocol}_depth_plus_one"] = deltas[f"{protocol}_depth_total"] == 1
    checks[f"{protocol}_expected_depth_two"] = deltas[f"{protocol}_depth_2"] == 1
    checks[f"{protocol}_depth_zero_matches_early"] = (
        deltas[f"{protocol}_depth_0"] == deltas[f"{protocol}_early_disconnect"]
    )

checks["malformed_unchanged"] = deltas["malformed"] == 0
checks["read_outcomes_unchanged"] = deltas["read_outcomes"] == 0
checks["write_outcomes_unchanged"] = deltas["write_outcomes"] == 0
passed = all(checks.values())
result = {
    "label": "Controlled VPS smoke test",
    "status": "pass" if passed else "fail",
    "start_utc": os.environ["SMOKE_START_UTC"],
    "end_utc": os.environ["SMOKE_END_UTC"],
    "checks": checks,
    "deltas": deltas,
    "note": "This controlled window is not unsolicited public field validation.",
}
output = directory / "smoke_result.json"
output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
output.chmod(0o600)
print(json.dumps(result, indent=2, sort_keys=True))
if not passed:
    raise SystemExit("controlled VPS smoke test failed; do not open the unsolicited window")
PY
REMOTE

printf 'Controlled VPS smoke test passed for %s to %s UTC.\n' "$smoke_start_utc" "$smoke_end_utc"
printf 'Next: review the result, open TCP 23/1883 according to the approved firewall policy, then run scripts/vps_field_start_observation.sh.\n'
