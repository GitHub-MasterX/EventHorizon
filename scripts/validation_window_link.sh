#!/usr/bin/env bash
set -euo pipefail

dashboard_uid=""
start_utc=""
end_utc=""
grafana_url="${GRAFANA_URL:-http://127.0.0.1:3000}"

usage() {
    printf 'Usage: %s --dashboard-uid UID --start UTC --end UTC [--grafana-url URL]\n' "$0"
}

while (($# > 0)); do
    case "$1" in
        --dashboard-uid) dashboard_uid="${2:-}"; shift 2 ;;
        --start) start_utc="${2:-}"; shift 2 ;;
        --end) end_utc="${2:-}"; shift 2 ;;
        --grafana-url) grafana_url="${2:-}"; shift 2 ;;
        --help|-h) usage; exit 0 ;;
        *) printf 'ERROR: unknown argument: %s\n' "$1" >&2; usage >&2; exit 2 ;;
    esac
done

[[ "$dashboard_uid" =~ ^[A-Za-z0-9_-]{1,40}$ ]] || { printf 'ERROR: invalid dashboard UID\n' >&2; exit 2; }
[[ -n "$start_utc" && -n "$end_utc" ]] || { usage >&2; exit 2; }
[[ "$grafana_url" =~ ^https?://[^[:space:]]+$ ]] || { printf 'ERROR: Grafana URL must use HTTP(S)\n' >&2; exit 2; }
grafana_url="${grafana_url%/}"

python3 - "$grafana_url" "$dashboard_uid" "$start_utc" "$end_utc" <<'PY'
import sys
from datetime import datetime, timezone
from urllib.parse import quote

base_url, uid, start_value, end_value = sys.argv[1:]

def epoch_ms(value):
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise SystemExit(f"invalid ISO-8601 timestamp {value!r}: {error}")
    if parsed.tzinfo is None:
        raise SystemExit("timestamps must include Z or an explicit UTC offset")
    return int(parsed.astimezone(timezone.utc).timestamp() * 1000)

start_ms = epoch_ms(start_value)
end_ms = epoch_ms(end_value)
if end_ms <= start_ms:
    raise SystemExit("end must be later than start")
print(f"{base_url}/d/{quote(uid, safe='')}?orgId=1&from={start_ms}&to={end_ms}&timezone=utc")
PY
