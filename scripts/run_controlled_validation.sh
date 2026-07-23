#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

usage() {
    cat <<'EOF'
Usage: run_controlled_validation.sh --protocol telnet|mqtt --sessions N --concurrency N [options]

Options:
  --profile exact|load|mixed       Default: load
  --scenario NAME                  Default: matrix (exact), depth2 (load), mixed (mixed)
  --settle-timeout SECONDS         Default: 60
  --output-dir DIRECTORY           Default: validation-output/controlled
  --max-temp-c CELSIUS             Default: 80
  --max-restarts N                 Default: 0
  --max-failure-rate FRACTION      Default: 0.05
  --min-disk-mib MIB               Default: 1024
  --target-host HOST               Default: 127.0.0.1
  --target-port PORT               Default: 23 for Telnet, 1883 for MQTT
  --compose-project NAME           Default: COMPOSE_PROJECT_NAME or eventhorizon
  --environment NAME               Default: raspberry-pi
  --annotation-name NAME           Create and close a Grafana validation annotation

For a non-loopback target, set EVENTHORIZON_CONTROLLED_TARGET_AUTHORIZED=yes
after confirming the single target is authorized and its public ports are
restricted to the validation source. PROMETHEUS_URL must address that target's
private Prometheus endpoint (normally through an SSH tunnel or on-host run).
EOF
}

die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 2
}

protocol=""
sessions=""
concurrency=""
profile="load"
scenario=""
settle_timeout=60
output_base="$REPO_ROOT/validation-output/controlled"
max_temp_c=80
max_restarts=0
max_failure_rate=0.05
min_disk_mib=1024
target_host=127.0.0.1
target_port=""
compose_project="${COMPOSE_PROJECT_NAME:-eventhorizon}"
environment="raspberry-pi"
annotation_name=""

while (($# > 0)); do
    case "$1" in
        --protocol) protocol="${2:-}"; shift 2 ;;
        --sessions) sessions="${2:-}"; shift 2 ;;
        --concurrency) concurrency="${2:-}"; shift 2 ;;
        --profile) profile="${2:-}"; shift 2 ;;
        --scenario) scenario="${2:-}"; shift 2 ;;
        --settle-timeout) settle_timeout="${2:-}"; shift 2 ;;
        --output-dir) output_base="${2:-}"; shift 2 ;;
        --max-temp-c) max_temp_c="${2:-}"; shift 2 ;;
        --max-restarts) max_restarts="${2:-}"; shift 2 ;;
        --max-failure-rate) max_failure_rate="${2:-}"; shift 2 ;;
        --min-disk-mib) min_disk_mib="${2:-}"; shift 2 ;;
        --target-host) target_host="${2:-}"; shift 2 ;;
        --target-port) target_port="${2:-}"; shift 2 ;;
        --compose-project) compose_project="${2:-}"; shift 2 ;;
        --environment) environment="${2:-}"; shift 2 ;;
        --annotation-name) annotation_name="${2:-}"; shift 2 ;;
        --help|-h) usage; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

[[ "$protocol" == telnet || "$protocol" == mqtt ]] || die "--protocol must be telnet or mqtt"
[[ "$sessions" =~ ^[0-9]+$ ]] && ((sessions >= 1 && sessions <= 10000)) || \
    die "--sessions must be between 1 and 10,000"
[[ "$concurrency" =~ ^[0-9]+$ ]] && ((concurrency >= 1 && concurrency <= 25)) || \
    die "--concurrency must be between 1 and 25"
[[ "$settle_timeout" =~ ^[0-9]+$ ]] && ((settle_timeout >= 15 && settle_timeout <= 600)) || \
    die "--settle-timeout must be between 15 and 600 seconds"
[[ "$max_restarts" =~ ^[0-9]+$ ]] || die "--max-restarts must be a non-negative integer"
[[ "$min_disk_mib" =~ ^[0-9]+$ ]] && ((min_disk_mib >= 256)) || die "--min-disk-mib must be at least 256"
[[ "$target_host" =~ ^[A-Za-z0-9._:-]+$ ]] || die "target host contains unsupported characters"
[[ "$compose_project" =~ ^[a-z0-9][a-z0-9_-]*$ ]] || die "invalid Compose project name"
[[ "$environment" =~ ^[A-Za-z0-9_.-]{1,40}$ ]] || die "invalid environment"
case "$profile" in exact|load|mixed) ;; *) die "unsupported profile" ;; esac

python3 - "$max_temp_c" "$max_failure_rate" <<'PY'
import sys
for name, value, low, high in (
    ("max temperature", sys.argv[1], 20, 100),
    ("max failure rate", sys.argv[2], 0, 1),
):
    try:
        number = float(value)
    except ValueError:
        raise SystemExit(f"{name} must be numeric")
    if not low <= number <= high:
        raise SystemExit(f"{name} must be between {low} and {high}")
PY

if ((sessions <= 10)); then
    ((concurrency <= 2)) || die "Stage 1 permits concurrency 1-2"
elif ((sessions <= 100)); then
    ((concurrency <= 10)) || die "Stage 2 permits concurrency 5-10 (or lower)"
else
    ((concurrency <= 25)) || die "Stage 3 permits concurrency 10-25 (or lower)"
fi

if [[ -z "$scenario" ]]; then
    case "$profile" in
        exact) scenario=matrix ;;
        load) scenario=depth2 ;;
        mixed) scenario=mixed ;;
    esac
fi

if [[ -z "$target_port" ]]; then
    [[ "$protocol" == telnet ]] && target_port=23 || target_port=1883
fi
[[ "$target_port" =~ ^[0-9]+$ ]] && ((target_port >= 1 && target_port <= 65535)) || die "invalid target port"

case "$target_host" in
    127.0.0.1|localhost|::1) host_category=loopback ;;
    *)
        [[ "${EVENTHORIZON_CONTROLLED_TARGET_AUTHORIZED:-}" == yes ]] || \
            die "non-loopback targets require EVENTHORIZON_CONTROLLED_TARGET_AUTHORIZED=yes"
        host_category=authorized-host
        ;;
esac

command -v python3 >/dev/null 2>&1 || die "python3 is required"
command -v docker >/dev/null 2>&1 || die "Docker is required for resource and restart validation"

if [[ "$environment" == vps ]]; then
    observation_state="${FIELD_OBSERVATION_STATE_FILE:-$REPO_ROOT/validation-output/observation_window.json}"
    if [[ -f "$observation_state" ]] && python3 - "$observation_state" <<'PY'
import json
import sys
from pathlib import Path

state = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
raise SystemExit(0 if state.get("status") == "running" else 1)
PY
    then
        die "an unsolicited observation is recorded as running; controlled VPS traffic must use a separate window"
    fi
fi

utc_stamp="$(date -u +%Y%m%dT%H%M%SZ)"
validation_id="${utc_stamp}-${protocol}-${profile}-${sessions}"
run_dir="$output_base/$validation_id"
[[ ! -e "$run_dir" ]] || die "output directory already exists: $run_dir"
mkdir -p "$run_dir"
chmod 700 "$run_dir"

annotation_started=false
close_annotation() {
    if $annotation_started; then
        "$SCRIPT_DIR/validation_annotation.sh" end \
            --name "$annotation_name" \
            --environment "$environment" \
            --validation-type controlled_load || true
    fi
}
trap close_annotation EXIT

if [[ -n "$annotation_name" ]]; then
    "$SCRIPT_DIR/validation_annotation.sh" start \
        --name "$annotation_name" \
        --environment "$environment" \
        --validation-type controlled_load
    annotation_started=true
fi

cd "$REPO_ROOT"
set +e
python3 "$SCRIPT_DIR/controlled_validation.py" \
    --validation-id "$validation_id" \
    --run-dir "$run_dir" \
    --protocol "$protocol" \
    --profile "$profile" \
    --scenario "$scenario" \
    --sessions "$sessions" \
    --concurrency "$concurrency" \
    --settle-timeout "$settle_timeout" \
    --max-temp-c "$max_temp_c" \
    --max-restarts "$max_restarts" \
    --max-failure-rate "$max_failure_rate" \
    --min-disk-mib "$min_disk_mib" \
    --target-host "$target_host" \
    --target-port "$target_port" \
    --target-host-category "$host_category" \
    --compose-project "$compose_project" \
    --environment "$environment" \
    --prometheus-url "${PROMETHEUS_URL:-http://127.0.0.1:9090}"
result=$?
set -e

if $annotation_started; then
    close_annotation
    annotation_started=false
fi
trap - EXIT

printf 'Validation evidence: %s\n' "$run_dir"
exit "$result"
