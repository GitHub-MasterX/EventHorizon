#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/vps_field_common.sh
source "$SCRIPT_DIR/vps_field_common.sh"
vps_field_load_env
vps_field_require_clean_commit

cd "$VPS_FIELD_REPO_ROOT"
vps_field_compose_args

command -v docker >/dev/null 2>&1 || vps_field_die "Docker is required for local Compose validation"
"${VPS_FIELD_COMPOSE[@]}" config --quiet
docker compose config --quiet

"$SCRIPT_DIR/vps_field_remote_preflight.sh"

printf '\nDeployment target summary\n'
printf '  branch: %s\n' "$DEPLOY_BRANCH"
printf '  commit: %s\n' "$DEPLOY_COMMIT"
printf '  project: %s\n' "$VPS_PROJECT_NAME"
printf '  public ports: 23/tcp, 1883/tcp\n'
printf '  private ports: 127.0.0.1:{3000,8081,9090,9101}\n'
printf '  duration: %s hours\n' "$FIELD_DURATION_HOURS"
printf '  admin source policy: %s (must already be reviewed manually)\n' "$ADMIN_SOURCE_CIDR"
printf '\nNo firewall rule will be changed by this script.\n'

if [[ ! -t 0 ]]; then
    vps_field_die "deployment confirmation requires an interactive terminal"
fi
read -r -p "Type DEPLOY $DEPLOY_COMMIT to clone/build/start the authorized VPS stack: " confirmation
[[ "$confirmation" == "DEPLOY $DEPLOY_COMMIT" ]] || vps_field_die "deployment cancelled"

memory_limit_arg="${FIELD_TARPIT_MEMORY_LIMIT:-__EVENTHORIZON_EMPTY__}"
vps_field_ssh bash -s -- \
    "$VPS_DEPLOY_DIR" \
    "$VPS_PROJECT_NAME" \
    "$REPOSITORY_URL" \
    "$DEPLOY_BRANCH" \
    "$DEPLOY_COMMIT" \
    "$FIELD_DURATION_HOURS" \
    "$SNAPSHOT_INTERVAL_HOURS" \
    "$FIELD_TARPIT_CPU_LIMIT" \
    "$memory_limit_arg" <<'REMOTE'
set -Eeuo pipefail

deploy_dir_input="$1"
project_name="$2"
repository_url="$3"
deploy_branch="$4"
deploy_commit="$5"
field_duration="$6"
snapshot_interval="$7"
cpu_limit="$8"
memory_limit="${9:-}"
[[ "$memory_limit" == "__EVENTHORIZON_EMPTY__" ]] && memory_limit=""

case "$deploy_dir_input" in
    "~/"*) deploy_dir="$HOME/${deploy_dir_input#\~/}" ;;
    /*) deploy_dir="$deploy_dir_input" ;;
    *) printf 'Invalid deployment directory\n' >&2; exit 1 ;;
esac

compose=(
    docker compose
    -p "$project_name"
    -f docker-compose.yml
    -f docker-compose.cost.yml
    -f docker-compose.field.yml
)
deployment_attempted=false

stop_after_failure() {
    exit_code=$?
    trap - ERR
    if $deployment_attempted && [[ -d "$deploy_dir/.git" ]]; then
        printf 'Critical deployment check failed; stopping the field project while preserving volumes and evidence.\n' >&2
        (cd "$deploy_dir" && "${compose[@]}" stop) || true
    fi
    exit "$exit_code"
}
trap stop_after_failure ERR

mkdir -p "$(dirname "$deploy_dir")"
if [[ ! -e "$deploy_dir" ]] || [[ -d "$deploy_dir" && -z "$(find "$deploy_dir" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
    git clone "$repository_url" "$deploy_dir"
elif [[ -d "$deploy_dir/.git" ]]; then
    existing_origin="$(git -C "$deploy_dir" remote get-url origin)"
    [[ "$existing_origin" == "$repository_url" ]] || {
        printf 'Existing deployment repository has an unexpected origin.\n' >&2
        exit 1
    }
    [[ -z "$(git -C "$deploy_dir" status --porcelain --untracked-files=normal)" ]] || {
        printf 'Existing deployment repository is dirty.\n' >&2
        exit 1
    }
else
    printf 'Deployment directory contains unrelated content.\n' >&2
    exit 1
fi

git -C "$deploy_dir" fetch --prune origin \
    "+refs/heads/$deploy_branch:refs/remotes/origin/$deploy_branch"
git -C "$deploy_dir" cat-file -e "$deploy_commit^{commit}"
remote_branch_tip="$(git -C "$deploy_dir" rev-parse "origin/$deploy_branch")"
[[ "$remote_branch_tip" == "$deploy_commit" ]] || {
    printf 'Fetched branch tip does not match requested commit.\n' >&2
    exit 1
}
git -C "$deploy_dir" checkout -B "$deploy_branch" "$deploy_commit"
[[ "$(git -C "$deploy_dir" rev-parse HEAD)" == "$deploy_commit" ]]
[[ -z "$(git -C "$deploy_dir" status --porcelain --untracked-files=normal)" ]]

cd "$deploy_dir"
export EVENTHORIZON_FIELD_AUTHORIZED=yes
export FIELD_PROJECT_NAME="$project_name"
export FIELD_TARPIT_CPU_LIMIT="$cpu_limit"
if [[ -n "$memory_limit" ]]; then
    export FIELD_TARPIT_MEMORY_LIMIT="$memory_limit"
else
    unset FIELD_TARPIT_MEMORY_LIMIT || true
fi

if ! command -v promtool >/dev/null 2>&1 && ! docker image inspect prom/prometheus >/dev/null 2>&1; then
    # The repository preflight uses the Prometheus image for promtool when no
    # host binary is installed. This pull occurs only after explicit approval.
    docker pull prom/prometheus
fi
scripts/field_validation_preflight.sh
docker compose config --quiet
"${compose[@]}" config --quiet

deployment_start_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
deployment_attempted=true
"${compose[@]}" up -d --build

deadline=$((SECONDS + 180))
services=(prometheus-exporter telnet_pit mqtt_pit prometheus grafana cadvisor)
while :; do
    all_healthy=true
    for service in "${services[@]}"; do
        container_id="$("${compose[@]}" ps -q "$service")"
        if [[ -z "$container_id" ]]; then
            all_healthy=false
            continue
        fi
        state="$(docker inspect --format '{{.State.Status}}' "$container_id")"
        health="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}not-configured{{end}}' "$container_id")"
        if [[ "$state" != "running" || "$health" == "unhealthy" || "$health" == "starting" ]]; then
            all_healthy=false
        fi
    done
    $all_healthy && break
    ((SECONDS < deadline)) || {
        printf 'Containers did not become healthy within 180 seconds.\n' >&2
        exit 1
    }
    sleep 3
done

curl -fsS http://127.0.0.1:9101/metrics >/dev/null
curl -fsS http://127.0.0.1:9090/-/healthy >/dev/null
curl -fsS http://127.0.0.1:3000/api/health >/dev/null
curl -fsS http://127.0.0.1:8081/healthz >/dev/null

for port in 3000 8081 9090 9101; do
    mapfile -t addresses < <(ss -H -ltn | awk -v suffix=":$port" '$4 ~ suffix "$" {print $4}')
    ((${#addresses[@]} > 0)) || {
        printf 'Management port %s has no listener.\n' "$port" >&2
        exit 1
    }
    for address in "${addresses[@]}"; do
        [[ "$address" == "127.0.0.1:$port" ]] || {
            printf 'Management port %s is unsafely bound at %s.\n' "$port" "$address" >&2
            exit 1
        }
    done
done

for port in 23 1883; do
    if ! ss -H -ltn | awk -v expected="0.0.0.0:$port" '$4 == expected {found=1} END {exit !found}'; then
        printf 'Public tarpit port %s is not bound at the expected IPv4 wildcard address.\n' "$port" >&2
        exit 1
    fi
done

mkdir -p validation-output
chmod 700 validation-output

export MANIFEST_DEPLOYMENT_START_UTC="$deployment_start_utc"
export MANIFEST_REPOSITORY_COMMIT="$deploy_commit"
export MANIFEST_BRANCH="$deploy_branch"
export MANIFEST_PROJECT="$project_name"
export MANIFEST_CPU_LIMIT="$cpu_limit"
export MANIFEST_MEMORY_LIMIT="${memory_limit:-unset}"
export MANIFEST_FIELD_DURATION="$field_duration"
export MANIFEST_SNAPSHOT_INTERVAL="$snapshot_interval"
export MANIFEST_DOCKER_VERSION="$(docker version --format '{{.Server.Version}}')"
export MANIFEST_COMPOSE_VERSION="$(docker compose version --short)"
python3 - <<'PY'
import json
import os
import platform
import urllib.request
from pathlib import Path

os_release = {}
for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
    if "=" in line:
        key, value = line.split("=", 1)
        os_release[key] = value.strip().strip('"')

controllers_path = Path("/sys/fs/cgroup/cgroup.controllers")
controllers = controllers_path.read_text(encoding="utf-8").split() if controllers_path.exists() else []
memory_supported = "memory" in controllers and Path("/sys/fs/cgroup/memory.current").is_file()

with urllib.request.urlopen("http://127.0.0.1:3000/api/health", timeout=5) as response:
    grafana_health = json.load(response)

timezones = set()
for dashboard_path in Path("grafana/dashboards").glob("*.json"):
    with dashboard_path.open(encoding="utf-8") as source:
        timezones.add(json.load(source).get("timezone"))
grafana_timezone = "utc" if timezones == {"utc"} else f"mixed:{sorted(str(value) for value in timezones)}"

scrape_interval = "unknown"
for line in Path("prometheus/prometheus.cost.yml").read_text(encoding="utf-8").splitlines():
    if "scrape_interval:" in line:
        scrape_interval = line.split(":", 1)[1].strip()
        break

manifest = {
    "deployment_start_utc": os.environ["MANIFEST_DEPLOYMENT_START_UTC"],
    "repository_commit": os.environ["MANIFEST_REPOSITORY_COMMIT"],
    "branch": os.environ["MANIFEST_BRANCH"],
    "compose_project_name": os.environ["MANIFEST_PROJECT"],
    "host_architecture": platform.machine(),
    "linux_distribution": os_release.get("PRETTY_NAME", "Linux"),
    "docker_version": os.environ["MANIFEST_DOCKER_VERSION"],
    "compose_version": os.environ["MANIFEST_COMPOSE_VERSION"],
    "prometheus_scrape_interval": scrape_interval,
    "grafana_version": grafana_health.get("version", "unknown"),
    "grafana_timezone": grafana_timezone,
    "public_tarpit_ports": ["0.0.0.0:23/tcp", "0.0.0.0:1883/tcp"],
    "private_management_bindings": [
        "127.0.0.1:3000/tcp",
        "127.0.0.1:8081/tcp",
        "127.0.0.1:9090/tcp",
        "127.0.0.1:9101/tcp",
    ],
    "cpu_limits": {"telnet_pit": os.environ["MANIFEST_CPU_LIMIT"], "mqtt_pit": os.environ["MANIFEST_CPU_LIMIT"]},
    "memory_limits": {"telnet_pit": os.environ["MANIFEST_MEMORY_LIMIT"], "mqtt_pit": os.environ["MANIFEST_MEMORY_LIMIT"]},
    "memory_controller_supported": memory_supported,
    "cgroup_controllers": controllers,
    "field_duration_target_hours": int(os.environ["MANIFEST_FIELD_DURATION"]),
    "snapshot_interval_hours": int(os.environ["MANIFEST_SNAPSHOT_INTERVAL"]),
}

output = Path("validation-output/deployment_manifest.json")
output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
output.chmod(0o600)
PY

"${compose[@]}" ps
deployment_attempted=false
trap - ERR
printf 'Deployment succeeded at exact commit %s.\n' "$deploy_commit"
printf 'Manifest: %s/validation-output/deployment_manifest.json\n' "$deploy_dir"
REMOTE

printf '\nDeployment completed. Run external verification before the controlled VPS smoke test:\n'
printf '  %s/scripts/vps_field_verify_external.sh\n' "$VPS_FIELD_REPO_ROOT"
