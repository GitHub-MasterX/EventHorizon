#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
usage: vps_field_remote_preflight.sh [--help]

Run the legacy read-only VPS preflight diagnostic. The supported deployment
entry point is scripts/vps_field_deploy.sh.
EOF
}

if (($# > 0)); then
    if (($# == 1)) && [[ "$1" == "--help" || "$1" == "-h" ]]; then
        usage
        exit 0
    fi
    printf 'ERROR: unsupported argument; use --help\n' >&2
    exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/vps_field_common.sh
source "$SCRIPT_DIR/vps_field_common.sh"
vps_field_load_env

printf 'Running read-only VPS preflight. No package, firewall, file, or container changes will be made.\n'

local_epoch="$(date -u +%s)"
memory_limit_arg="${FIELD_TARPIT_MEMORY_LIMIT:-__EVENTHORIZON_EMPTY__}"
vps_field_ssh bash -s -- \
    "$VPS_DEPLOY_DIR" \
    "$VPS_PROJECT_NAME" \
    "$REPOSITORY_URL" \
    "$local_epoch" \
    "$memory_limit_arg" <<'REMOTE'
set -u

deploy_dir_input="$1"
project_name="$2"
repository_url="$3"
reference_epoch="$4"
requested_memory_limit="${5:-}"
[[ "$requested_memory_limit" == "__EVENTHORIZON_EMPTY__" ]] && requested_memory_limit=""
failures=0

case "$deploy_dir_input" in
    "~/"*) deploy_dir="$HOME/${deploy_dir_input#\~/}" ;;
    /*) deploy_dir="$deploy_dir_input" ;;
    *) printf 'invalid deployment directory\n' >&2; exit 1 ;;
esac

clean_cell() {
    local value="$1"
    value="${value//$'\n'/; }"
    value="${value//|//}"
    printf '%.120s' "$value"
}

row() {
    printf '%-28s | %-40s | %-28s | %s\n' \
        "$(clean_cell "$1")" "$(clean_cell "$2")" "$(clean_cell "$3")" "$4"
}

pass() { row "$1" "$2" "$3" PASS; }
warn() { row "$1" "$2" "$3" WARN; }
fail() { row "$1" "$2" "$3" FAIL; failures=$((failures + 1)); }

printf '%-28s | %-40s | %-28s | %s\n' 'Check' 'Observed' 'Required' 'Result'
printf '%s\n' '-----------------------------+------------------------------------------+------------------------------+-------'

if [[ "$(uname -s 2>/dev/null)" == "Linux" ]]; then
    os_name="$(. /etc/os-release 2>/dev/null; printf '%s' "${PRETTY_NAME:-Linux}")"
    pass 'Operating system' "$os_name" 'authorized supported Linux'
else
    fail 'Operating system' "$(uname -s 2>/dev/null || printf unknown)" 'Linux'
fi

pass 'CPU architecture' "$(uname -m 2>/dev/null || printf unknown)" 'Docker-supported architecture'
cpu_count="$(getconf _NPROCESSORS_ONLN 2>/dev/null || nproc 2>/dev/null || printf 0)"
if [[ "$cpu_count" =~ ^[0-9]+$ ]] && ((cpu_count >= 2)); then
    pass 'Available CPU' "$cpu_count logical CPUs" 'at least 2'
else
    fail 'Available CPU' "$cpu_count logical CPUs" 'at least 2'
fi

memory_kib="$(awk '/MemAvailable:/ {print $2}' /proc/meminfo 2>/dev/null)"
memory_kib="${memory_kib:-0}"
memory_mib=$((memory_kib / 1024))
if ((memory_mib >= 2048)); then
    pass 'Available memory' "${memory_mib} MiB" 'at least 1024 MiB; 2048 recommended'
elif ((memory_mib >= 1024)); then
    warn 'Available memory' "${memory_mib} MiB" '2048 MiB recommended'
else
    fail 'Available memory' "${memory_mib} MiB" 'at least 1024 MiB'
fi

disk_kib="$(df -Pk "$(dirname "$deploy_dir")" 2>/dev/null | awk 'NR == 2 {print $4}')"
if [[ -z "$disk_kib" ]]; then
    disk_kib="$(df -Pk "$HOME" | awk 'NR == 2 {print $4}')"
fi
disk_mib=$((disk_kib / 1024))
if ((disk_mib >= 5120)); then
    pass 'Available disk' "${disk_mib} MiB" 'at least 5120 MiB'
else
    fail 'Available disk' "${disk_mib} MiB" 'at least 5120 MiB'
fi

remote_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || printf unavailable)"
remote_epoch="$(date -u +%s 2>/dev/null || printf 0)"
clock_delta=$((remote_epoch - reference_epoch))
((clock_delta < 0)) && clock_delta=$((-clock_delta))
if ((clock_delta <= 300)); then
    pass 'Current UTC time' "$remote_utc; delta ${clock_delta}s" 'within 300s of control host'
else
    fail 'Current UTC time' "$remote_utc; delta ${clock_delta}s" 'within 300s of control host'
fi

if command -v timedatectl >/dev/null 2>&1; then
    ntp_state="$(timedatectl show -p NTPSynchronized --value 2>/dev/null || printf unknown)"
    if [[ "$ntp_state" == "yes" ]]; then
        pass 'NTP synchronization' "$ntp_state" 'yes'
    else
        warn 'NTP synchronization' "$ntp_state" 'yes or documented equivalent'
    fi
else
    warn 'NTP synchronization' 'timedatectl unavailable' 'verify provider time synchronization'
fi

if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    pass 'Docker Engine' "$(docker version --format '{{.Server.Version}}' 2>/dev/null)" 'installed and daemon reachable'
else
    fail 'Docker Engine' 'missing or daemon unavailable' 'installed and daemon reachable'
fi

if docker compose version >/dev/null 2>&1; then
    pass 'Docker Compose' "$(docker compose version --short 2>/dev/null || docker compose version)" 'Compose plugin available'
else
    fail 'Docker Compose' 'unavailable' 'Compose plugin available'
fi

if command -v git >/dev/null 2>&1; then
    pass 'Git' "$(git --version)" 'installed'
else
    fail 'Git' 'unavailable' 'installed'
fi
if command -v curl >/dev/null 2>&1; then
    pass 'curl' "$(curl --version | head -n 1)" 'installed'
else
    fail 'curl' 'unavailable' 'required by field health checks'
fi
if command -v python3 >/dev/null 2>&1; then
    pass 'Python' "$(python3 --version 2>&1)" 'Python 3 for aggregate snapshots'
else
    fail 'Python' 'unavailable' 'Python 3 for aggregate snapshots'
fi
if command -v ss >/dev/null 2>&1; then
    pass 'Socket inspection' "$(ss --version 2>&1 | head -n 1)" 'ss available for binding checks'
else
    fail 'Socket inspection' 'ss unavailable' 'ss available for binding checks'
fi

cgroup_type="$(stat -fc %T /sys/fs/cgroup 2>/dev/null || printf unknown)"
if [[ "$cgroup_type" == "cgroup2fs" ]]; then
    pass 'cgroup version' 'v2' 'v2 preferred'
else
    warn 'cgroup version' "$cgroup_type" 'v2 preferred; document limitation'
fi
controllers="$(cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null || printf unavailable)"
pass 'cgroup controllers' "$controllers" 'cpu and runtime controllers available'
memory_supported=false
if [[ "$controllers" == *memory* && -r /sys/fs/cgroup/memory.current ]]; then
    memory_supported=true
    if [[ -n "$requested_memory_limit" && "$requested_memory_limit" != "0" ]]; then
        pass 'Memory controller' 'memory.current available' "limit requested: $requested_memory_limit"
    else
        fail 'Memory controller' 'memory.current available' 'set FIELD_TARPIT_MEMORY_LIMIT for this capable host'
    fi
else
    if [[ -n "$requested_memory_limit" && "$requested_memory_limit" != "0" ]]; then
        fail 'Memory controller' 'unavailable' 'required by requested memory limit'
    else
        warn 'Memory controller' 'unavailable' 'memory metric remains deferred'
    fi
fi

docker_warnings="$(docker info --format '{{range .Warnings}}{{println .}}{{end}}' 2>/dev/null || true)"
if grep -qi 'no memory limit support' <<<"$docker_warnings"; then
    if [[ -n "$requested_memory_limit" && "$requested_memory_limit" != "0" ]]; then
        fail 'Docker memory limits' 'unsupported' 'required by requested memory limit'
    else
        warn 'Docker memory limits' 'unsupported' 'leave memory deferred'
    fi
else
    pass 'Docker memory limits' 'no unsupported warning' 'supported when configured'
fi

container_list="$(docker ps -a --format '{{.Names}}' 2>/dev/null || true)"
if [[ -z "$container_list" ]]; then
    pass 'Existing containers' 'none' 'dedicated VPS with no unrelated workload'
else
    fail 'Existing containers' "$(tr '\n' ',' <<<"$container_list")" 'none before initial deployment'
fi

compose_projects="$(docker compose ls --format json 2>/dev/null || true)"
if [[ -z "$compose_projects" || "$compose_projects" == "[]" ]]; then
    pass 'Existing Compose projects' 'none' 'no project or container-name conflict'
else
    fail 'Existing Compose projects' "$compose_projects" 'none before initial deployment'
fi

for port in 23 1883 3000 8081 9090 9101; do
    listeners="$(ss -H -ltn 2>/dev/null | awk -v suffix=":$port" '$4 ~ suffix "$" {print $4}' | paste -sd, -)"
    if [[ -z "$listeners" ]]; then
        pass "TCP port $port" 'available' 'no listener before deployment'
    else
        fail "TCP port $port" "$listeners" 'no listener before deployment'
    fi
done

firewall_observed='not detected'
if command -v ufw >/dev/null 2>&1; then
    firewall_observed="ufw: $(sudo -n ufw status 2>/dev/null | head -n 1 || printf status-unavailable)"
elif command -v nft >/dev/null 2>&1; then
    if sudo -n nft list ruleset >/dev/null 2>&1; then
        firewall_observed='nftables ruleset readable'
    else
        firewall_observed='nftables detected; status requires administrator review'
    fi
elif command -v iptables >/dev/null 2>&1; then
    if sudo -n iptables -S >/dev/null 2>&1; then
        firewall_observed='iptables rules readable'
    else
        firewall_observed='iptables detected; status requires administrator review'
    fi
fi
warn 'Host firewall' "$firewall_observed" 'manual review; no automatic changes'
warn 'Provider firewall' 'not observable from guest' 'manual provider-policy and rule review'

if [[ ! -e "$deploy_dir" ]]; then
    pass 'Deployment directory' 'absent' 'absent, empty, or clean matching repository'
elif [[ ! -d "$deploy_dir" ]]; then
    fail 'Deployment directory' 'exists and is not a directory' 'absent, empty, or clean matching repository'
elif [[ -z "$(find "$deploy_dir" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)" ]]; then
    pass 'Deployment directory' 'empty' 'absent, empty, or clean matching repository'
elif [[ -d "$deploy_dir/.git" ]]; then
    existing_origin="$(git -C "$deploy_dir" remote get-url origin 2>/dev/null || printf unavailable)"
    existing_status="$(git -C "$deploy_dir" status --porcelain --untracked-files=normal 2>/dev/null || printf unknown)"
    if [[ "$existing_origin" == "$repository_url" && -z "$existing_status" ]]; then
        pass 'Deployment directory' 'clean matching Git repository' 'matching origin and clean tree'
    else
        fail 'Deployment directory' "origin=$existing_origin; dirty=$([[ -n "$existing_status" ]] && printf yes || printf no)" 'matching origin and clean tree'
    fi
else
    fail 'Deployment directory' 'contains unrelated content' 'absent, empty, or clean matching repository'
fi

if ((failures > 0)); then
    printf '\nRemote preflight blocked deployment with %d critical failure(s).\n' "$failures" >&2
    exit 1
fi
printf '\nRemote read-only preflight passed. Warnings still require operator review.\n'
REMOTE
