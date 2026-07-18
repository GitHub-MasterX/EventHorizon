#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/vps_field_common.sh
source "$SCRIPT_DIR/vps_field_common.sh"
vps_field_load_env

if [[ ! -t 0 ]]; then
    vps_field_die "stop confirmation requires an interactive terminal"
fi
read -r -p "Type STOP $VPS_PROJECT_NAME to capture final evidence and stop the VPS field stack: " confirmation
[[ "$confirmation" == "STOP $VPS_PROJECT_NAME" ]] || vps_field_die "stop cancelled"

vps_field_ssh bash -s -- "$VPS_DEPLOY_DIR" "$VPS_PROJECT_NAME" "$DEPLOY_COMMIT" <<'REMOTE'
set -euo pipefail
deploy_dir_input="$1"
project_name="$2"
expected_commit="$3"
case "$deploy_dir_input" in
    "~/"*) deploy_dir="$HOME/${deploy_dir_input#\~/}" ;;
    /*) deploy_dir="$deploy_dir_input" ;;
    *) exit 1 ;;
esac
cd "$deploy_dir"
[[ "$(git rev-parse HEAD)" == "$expected_commit" ]]

python3 - <<'PY'
import json
from datetime import datetime, timezone
from pathlib import Path

path = Path("validation-output/observation_window.json")
if not path.is_file():
    raise SystemExit("observation window evidence is missing")
document = json.loads(path.read_text(encoding="utf-8"))
end = datetime.now(timezone.utc)
document["observation_end_utc"] = end.isoformat().replace("+00:00", "Z")
document["status"] = "stopping"
if document.get("start_utc"):
    start = datetime.fromisoformat(document["start_utc"].replace("Z", "+00:00"))
    document["actual_duration_hours"] = round((end - start).total_seconds() / 3600, 4)
path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
path.chmod(0o600)
PY

stop_report="$(FIELD_PROJECT_NAME="$project_name" \
FIELD_VALIDATION_OUTPUT_DIR="$deploy_dir/validation-output" \
    scripts/field_validation_stop.sh)"
final_snapshot="$(awk -F= '$1 == "final_snapshot" {print $2; exit}' "$stop_report")"
[[ -n "$final_snapshot" && -f "$final_snapshot" ]] || {
    printf 'The field stop report did not identify a final aggregate snapshot.\n' >&2
    exit 1
}

export OBSERVATION_FINAL_SNAPSHOT="$final_snapshot"
python3 - <<'PY'
import json
import os
from pathlib import Path

path = Path("validation-output/observation_window.json")
document = json.loads(path.read_text(encoding="utf-8"))
document["final_snapshot_location"] = os.environ["OBSERVATION_FINAL_SNAPSHOT"]
path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
path.chmod(0o600)
PY

compose=(docker compose -p "$project_name" -f docker-compose.yml -f docker-compose.cost.yml -f docker-compose.field.yml)
if [[ -n "$("${compose[@]}" ps -q)" ]]; then
    printf 'One or more field containers remain running after stop.\n' >&2
    exit 1
fi
for port in 23 1883; do
    if ss -H -ltn | awk -v suffix=":$port" '$4 ~ suffix "$" {found=1} END {exit !found}'; then
        printf 'Public tarpit port %s remains listening after stop.\n' "$port" >&2
        exit 1
    fi
done

python3 - <<'PY'
import json
from pathlib import Path

path = Path("validation-output/observation_window.json")
document = json.loads(path.read_text(encoding="utf-8"))
document["status"] = "stopped"
path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
path.chmod(0o600)
PY

printf 'Field project stopped; containers and volumes remain available for inspection.\n'
printf 'Public TCP 23 and 1883 have no listener. Close their firewall rules manually.\n'
REMOTE

utc_stamp="$(date -u +%Y%m%dT%H%M%SZ)"
destination="$VPS_FIELD_REPO_ROOT/validation-output/vps-field-$utc_stamp"
archive="$(mktemp /tmp/eventhorizon-vps-field-evidence.XXXXXX.tar)"
cleanup() { rm -f "$archive"; }
trap cleanup EXIT
mkdir -p "$destination"

vps_field_ssh bash -s -- "$VPS_DEPLOY_DIR" >"$archive" <<'REMOTE'
set -euo pipefail
deploy_dir_input="$1"
case "$deploy_dir_input" in
    "~/"*) deploy_dir="$HOME/${deploy_dir_input#\~/}" ;;
    /*) deploy_dir="$deploy_dir_input" ;;
    *) exit 1 ;;
esac
cd "$deploy_dir/validation-output"

mapfile -d '' allowed_files < <(
    find . -type f \( \
        -name 'deployment_manifest.json' -o \
        -name 'observation_window.json' -o \
        -path './smoke/*.json' -o \
        -path './smoke/*.txt' -o \
        -path './snapshots/field-snapshot-*.txt' -o \
        -name 'field-snapshot-*.txt' -o \
        -name 'field-stop-*.txt' \
    \) -print0
)
((${#allowed_files[@]} > 0)) || {
    printf 'No aggregate evidence files matched the retrieval allowlist.\n' >&2
    exit 1
}
printf '%s\0' "${allowed_files[@]}" | tar --null -T - -cf -
REMOTE

tar -xf "$archive" -C "$destination"
chmod -R go-rwx "$destination"

printf 'Aggregate evidence retrieved to %s\n' "$destination"
printf 'Prometheus/Grafana volumes and remote validation-output were preserved.\n'
printf 'No raw payload log, credential file, private key, public IP list, or Prometheus storage volume was retrieved.\n'
