#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/vps_field_common.sh
source "$SCRIPT_DIR/vps_field_common.sh"
vps_field_load_env

command -v nmap >/dev/null 2>&1 || vps_field_die "nmap is required to distinguish open, closed, and filtered states"

ports=(23 1883 3000 8081 9090 9101)
expected_open=(23 1883)
scan_output="$(mktemp)"
cleanup() { rm -f "$scan_output"; }
trap cleanup EXIT

# This is a low-impact TCP-connect check against one authorized host and six
# explicit ports. It does not scan a range, discover hosts, or use raw SYNs.
nmap \
    -Pn \
    -n \
    -sT \
    --max-retries 1 \
    --host-timeout 30s \
    -p 23,1883,3000,8081,9090,9101 \
    -oG "$scan_output" \
    "$VPS_HOST" >/dev/null

grep -q 'Ports:' "$scan_output" || vps_field_die "nmap did not return a port result for the authorized VPS host"

printf '%-8s | %-18s | %-18s | %s\n' 'Port' 'Expected' 'Observed' 'Result'
printf '%s\n' '---------+--------------------+--------------------+-------'
failures=0
for port in "${ports[@]}"; do
    state="$(grep 'Ports:' "$scan_output" | tr ', ' '\n\n' | awk -F/ -v wanted="$port" '$1 == wanted {print $2; exit}')"
    state="${state:-not-reported}"

    expected='closed or filtered'
    result=PASS
    if [[ "$port" == 23 || "$port" == 1883 ]]; then
        expected=open
        [[ "$state" == "open" ]] || result=FAIL
    else
        [[ "$state" == "closed" || "$state" == "filtered" ]] || result=FAIL
    fi
    [[ "$result" == PASS ]] || failures=$((failures + 1))
    printf '%-8s | %-18s | %-18s | %s\n' "$port/tcp" "$expected" "$state" "$result"
done

if ((failures > 0)); then
    printf 'External binding verification failed for %d port(s).\n' "$failures" >&2
    exit 1
fi
printf 'External binding verification passed for the single authorized VPS host.\n'
