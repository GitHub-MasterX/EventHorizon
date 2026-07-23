#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
GRAFANA_URL="${GRAFANA_URL:-http://127.0.0.1:3000}"
STATE_DIR="${VALIDATION_ANNOTATION_STATE_DIR:-$REPO_ROOT/validation-output/annotations}"

usage() {
    printf 'Usage: %s start|end --name NAME [options]\n' "$0"
    printf 'Options: --dashboard-uid UID --environment NAME --validation-type TYPE --at UTC\n'
    printf 'Authentication: set GRAFANA_TOKEN, or both GRAFANA_USER and GRAFANA_PASSWORD.\n'
}

die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

[[ $# -ge 1 ]] || { usage >&2; exit 2; }
operation="$1"
shift
[[ "$operation" == start || "$operation" == end ]] || { usage >&2; exit 2; }

name=""
dashboard_uid="eh-interaction-depth"
environment="raspberry-pi"
validation_type="controlled_load"
event_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

while (($# > 0)); do
    case "$1" in
        --name) name="${2:-}"; shift 2 ;;
        --dashboard-uid) dashboard_uid="${2:-}"; shift 2 ;;
        --environment) environment="${2:-}"; shift 2 ;;
        --validation-type) validation_type="${2:-}"; shift 2 ;;
        --at) event_utc="${2:-}"; shift 2 ;;
        --help|-h) usage; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

[[ -n "$name" && ${#name} -le 120 && "$name" != *$'\n'* && "$name" != *$'\r'* ]] || \
    die "--name must contain 1-120 characters on one line"
[[ "$dashboard_uid" =~ ^[A-Za-z0-9_-]{1,40}$ ]] || die "invalid dashboard UID"
[[ "$environment" =~ ^[A-Za-z0-9_.-]{1,40}$ ]] || die "invalid environment"
case "$validation_type" in
    exact|controlled_load|vps_smoke|vps_controlled_load|public_observation|persistence) ;;
    *) die "unsupported validation type" ;;
esac

auth_args=()
if [[ -n "${GRAFANA_TOKEN:-}" ]]; then
    auth_args=(-H "Authorization: Bearer $GRAFANA_TOKEN")
elif [[ -n "${GRAFANA_USER:-}" && -n "${GRAFANA_PASSWORD:-}" ]]; then
    auth_args=(-u "$GRAFANA_USER:$GRAFANA_PASSWORD")
else
    die "set GRAFANA_TOKEN or GRAFANA_USER and GRAFANA_PASSWORD; secrets are never read from the repository"
fi

readarray -t normalized_time < <(python3 - "$event_utc" <<'PY'
import sys
from datetime import datetime, timezone

value = sys.argv[1]
try:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
except ValueError as error:
    raise SystemExit(f"invalid ISO-8601 timestamp: {error}")
if parsed.tzinfo is None:
    raise SystemExit("timestamp must include Z or an explicit UTC offset")
parsed = parsed.astimezone(timezone.utc)
print(parsed.isoformat().replace("+00:00", "Z"))
print(int(parsed.timestamp() * 1000))
PY
)
event_utc="${normalized_time[0]}"
event_ms="${normalized_time[1]}"

state_key="$(python3 - "$name" <<'PY'
import hashlib
import sys
print(hashlib.sha256(sys.argv[1].encode()).hexdigest())
PY
)"
state_file="$STATE_DIR/$state_key.json"
response_file="$(mktemp)"
payload_file="$(mktemp)"
cleanup() {
    rm -f "$response_file" "$payload_file"
}
trap cleanup EXIT
mkdir -p "$STATE_DIR"
chmod 700 "$STATE_DIR"

cd "$REPO_ROOT"
commit="$(git rev-parse HEAD)"

if [[ "$operation" == start ]]; then
    if [[ -f "$state_file" ]] && python3 - "$state_file" <<'PY'
import json
import sys
from pathlib import Path
state = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
raise SystemExit(0 if state.get("status") == "running" else 1)
PY
    then
        die "an annotation with this name is already running"
    fi

    python3 - "$payload_file" "$dashboard_uid" "$name" "$event_utc" "$event_ms" \
        "$commit" "$environment" "$validation_type" <<'PY'
import json
import sys
from pathlib import Path

path, uid, name, start_utc, start_ms, commit, environment, validation_type = sys.argv[1:]
document = {
    "dashboardUID": uid,
    "time": int(start_ms),
    "tags": ["eventhorizon-validation", f"environment:{environment}", f"validation:{validation_type}"],
    "text": (f"name={name}\nstart_utc={start_utc}\nend_utc=pending\n"
             f"git_commit={commit}\nenvironment={environment}\nvalidation_type={validation_type}"),
}
Path(path).write_text(json.dumps(document), encoding="utf-8")
PY

    http_status="$(curl --silent --show-error --output "$response_file" --write-out '%{http_code}' \
        "${auth_args[@]}" -H 'Content-Type: application/json' --data-binary "@$payload_file" \
        "$GRAFANA_URL/api/annotations")"
    [[ "$http_status" == 200 ]] || die "Grafana annotation create failed with HTTP $http_status"

    python3 - "$response_file" "$state_file" "$name" "$dashboard_uid" "$event_utc" "$event_ms" \
        "$commit" "$environment" "$validation_type" <<'PY'
import json
import sys
from pathlib import Path

response_path, state_path, name, uid, start_utc, start_ms, commit, environment, validation_type = sys.argv[1:]
response = json.loads(Path(response_path).read_text(encoding="utf-8"))
annotation_id = response.get("id")
if not isinstance(annotation_id, int):
    raise SystemExit("Grafana response did not contain an annotation id")
state = {
    "annotation_id": annotation_id,
    "dashboard_uid": uid,
    "environment": environment,
    "git_commit": commit,
    "name": name,
    "start_ms": int(start_ms),
    "start_utc": start_utc,
    "status": "running",
    "validation_type": validation_type,
}
path = Path(state_path)
path.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
path.chmod(0o600)
print(json.dumps(state, indent=2, sort_keys=True))
PY
    exit 0
fi

[[ -f "$state_file" ]] || die "no local running annotation state exists for this name"
readarray -t state_values < <(python3 - "$state_file" "$name" <<'PY'
import json
import sys
from pathlib import Path

state = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
if state.get("name") != sys.argv[2] or state.get("status") != "running":
    raise SystemExit("annotation state is not the requested running window")
for key in ("annotation_id", "dashboard_uid", "start_utc", "start_ms", "git_commit", "environment", "validation_type"):
    print(state[key])
PY
)
annotation_id="${state_values[0]}"
dashboard_uid="${state_values[1]}"
start_utc="${state_values[2]}"
start_ms="${state_values[3]}"
commit="${state_values[4]}"
environment="${state_values[5]}"
validation_type="${state_values[6]}"
((event_ms >= start_ms)) || die "end timestamp precedes start timestamp"

python3 - "$payload_file" "$name" "$start_utc" "$start_ms" "$event_utc" "$event_ms" \
    "$commit" "$environment" "$validation_type" <<'PY'
import json
import sys
from pathlib import Path

path, name, start_utc, start_ms, end_utc, end_ms, commit, environment, validation_type = sys.argv[1:]
document = {
    "time": int(start_ms),
    "timeEnd": int(end_ms),
    "tags": ["eventhorizon-validation", f"environment:{environment}", f"validation:{validation_type}"],
    "text": (f"name={name}\nstart_utc={start_utc}\nend_utc={end_utc}\n"
             f"git_commit={commit}\nenvironment={environment}\nvalidation_type={validation_type}"),
}
Path(path).write_text(json.dumps(document), encoding="utf-8")
PY

http_status="$(curl --silent --show-error --output "$response_file" --write-out '%{http_code}' \
    "${auth_args[@]}" -X PATCH -H 'Content-Type: application/json' --data-binary "@$payload_file" \
    "$GRAFANA_URL/api/annotations/$annotation_id")"
[[ "$http_status" == 200 ]] || die "Grafana annotation update failed with HTTP $http_status"

python3 - "$state_file" "$event_utc" "$event_ms" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
state = json.loads(path.read_text(encoding="utf-8"))
state.update({"end_utc": sys.argv[2], "end_ms": int(sys.argv[3]), "status": "ended"})
path.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
path.chmod(0o600)
print(json.dumps(state, indent=2, sort_keys=True))
PY
