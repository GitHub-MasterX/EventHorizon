#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
output_directory="$repo_root/validation-output/ci-smoke"
unset CI_SMOKE_REASON || true

usage() {
    printf 'Usage: %s [--output-dir DIRECTORY]\n' "$0"
}

while (($# > 0)); do
    case "$1" in
        --output-dir)
            [[ $# -ge 2 ]] || {
                usage >&2
                exit 2
            }
            output_directory="$2"
            shift 2
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            usage >&2
            exit 2
            ;;
    esac
done

run_component="${GITHUB_RUN_ID:-local}"
attempt_component="${GITHUB_RUN_ATTEMPT:-1}"
if [[ "$run_component" == local ]]; then
    run_component="local-$$"
fi
project_name="eventhorizon-ci-${run_component}-${attempt_component}"
export CI_PROJECT_NAME="$project_name"
export COMPOSE_PROGRESS=plain

compose=(
    docker compose
    --env-file "$repo_root/deploy/compose-ci.env"
    --project-name "$project_name"
    --file "$repo_root/docker-compose.yml"
    --file "$repo_root/docker-compose.cost.yml"
    --file "$repo_root/docker-compose.field.yml"
    --file "$repo_root/docker-compose.ci.yml"
)

mkdir -p "$output_directory/diagnostics"
chmod 700 "$output_directory" "$output_directory/diagnostics"
started_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

finish() {
    exit_code=$?
    trap - EXIT
    set +e
    "${compose[@]}" ps --all \
        >"$output_directory/diagnostics/compose-ps.txt" 2>&1
    if ((exit_code != 0)); then
        "${compose[@]}" logs --no-color \
            >"$output_directory/diagnostics/container-logs.txt" 2>&1
    fi
    if [[ ! -f "$output_directory/summary.json" ]]; then
        CI_SMOKE_STARTED="$started_utc" \
        CI_SMOKE_EXIT="$exit_code" \
        CI_SMOKE_OUTPUT="$output_directory/summary.json" \
            python3 - <<'PY'
import json
import os
from datetime import datetime, timezone
from pathlib import Path

document = {
    "schema_version": 1,
    "status": {
        "0": "PASS",
        "2": "BLOCKED",
    }.get(os.environ["CI_SMOKE_EXIT"], "FAIL"),
    "started_utc": os.environ["CI_SMOKE_STARTED"],
    "finished_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "protocols": [],
}
reason = os.environ.get("CI_SMOKE_REASON")
if reason:
    document["reason"] = reason
Path(os.environ["CI_SMOKE_OUTPUT"]).write_text(
    json.dumps(document, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY
    fi
    "${compose[@]}" down --volumes --remove-orphans --timeout 10 \
        >"$output_directory/diagnostics/compose-down.txt" 2>&1
    exit "$exit_code"
}
trap finish EXIT

docker_architecture="$(docker info --format '{{.Architecture}}')"
if [[ "$docker_architecture" != amd64 && "$docker_architecture" != x86_64 ]]; then
    export CI_SMOKE_REASON="The deterministic CI smoke stack requires a native linux/amd64 Docker engine."
    printf '%s Observed Docker architecture: %s\n' \
        "$CI_SMOKE_REASON" "$docker_architecture" >&2
    exit 2
fi

"${compose[@]}" config --format json \
    >"$output_directory/diagnostics/compose-config.json"

python3 - "$output_directory/diagnostics/compose-config.json" <<'PY'
import json
import sys
from pathlib import Path

config = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
expected = {
    "prometheus-exporter": ("127.0.0.1", "19101"),
    "telnet_pit": ("127.0.0.1", "23230"),
    "mqtt_pit": ("127.0.0.1", "21883"),
    "prometheus": ("127.0.0.1", "19090"),
    "grafana": ("127.0.0.1", "13000"),
    "cadvisor": ("127.0.0.1", "18081"),
}
for service_name, binding in expected.items():
    ports = config["services"][service_name].get("ports", [])
    if len(ports) != 1:
        raise SystemExit(f"{service_name} does not have one isolated CI port")
    observed = (ports[0].get("host_ip"), str(ports[0].get("published")))
    if observed != binding:
        raise SystemExit(f"{service_name} has unsafe CI binding {observed!r}")
PY

"${compose[@]}" up --detach --build 2>&1 \
    | tee "$output_directory/diagnostics/compose-up.txt"

wait_http() {
    local label="$1"
    local url="$2"
    local deadline=$((SECONDS + 180))
    until curl --fail --silent --show-error "$url" >/dev/null; do
        ((SECONDS < deadline)) || {
            printf 'Timed out waiting for %s\n' "$label" >&2
            return 1
        }
        sleep 3
    done
}

wait_http exporter http://127.0.0.1:19101/metrics
wait_http prometheus http://127.0.0.1:19090/-/healthy

# Wait for a fresh scrape before taking the zero-active baseline.
sleep 20
controlled_output="$output_directory/controlled"
mkdir -p "$controlled_output"
chmod 700 "$controlled_output"

PROMETHEUS_URL=http://127.0.0.1:19090 \
    "$script_dir/run_controlled_validation.sh" \
    --protocol telnet \
    --profile exact \
    --scenario matrix \
    --sessions 4 \
    --concurrency 2 \
    --settle-timeout 90 \
    --min-disk-mib 256 \
    --target-host 127.0.0.1 \
    --target-port 23230 \
    --compose-project "$project_name" \
    --environment ci \
    --output-dir "$controlled_output"

PROMETHEUS_URL=http://127.0.0.1:19090 \
    "$script_dir/run_controlled_validation.sh" \
    --protocol mqtt \
    --profile exact \
    --scenario matrix \
    --sessions 4 \
    --concurrency 2 \
    --settle-timeout 90 \
    --min-disk-mib 256 \
    --target-host 127.0.0.1 \
    --target-port 21883 \
    --compose-project "$project_name" \
    --environment ci \
    --output-dir "$controlled_output"

CI_SMOKE_STARTED="$started_utc" \
CI_SMOKE_CONTROLLED="$controlled_output" \
CI_SMOKE_OUTPUT="$output_directory/summary.json" \
    python3 - <<'PY'
import json
import os
from datetime import datetime, timezone
from pathlib import Path

summaries = []
for path in sorted(Path(os.environ["CI_SMOKE_CONTROLLED"]).glob("*/summary.json")):
    summary = json.loads(path.read_text(encoding="utf-8"))
    summaries.append(
        {
            "validation_id": summary["validation_id"],
            "status": summary["status"],
            "checks": summary["checks"],
        }
    )
if len(summaries) != 2 or any(item["status"] != "PASS" for item in summaries):
    raise SystemExit("Telnet and MQTT deterministic summaries must both pass")

document = {
    "schema_version": 1,
    "status": "PASS",
    "started_utc": os.environ["CI_SMOKE_STARTED"],
    "finished_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "protocols": summaries,
}
Path(os.environ["CI_SMOKE_OUTPUT"]).write_text(
    json.dumps(document, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
print(json.dumps(document, indent=2, sort_keys=True))
PY
