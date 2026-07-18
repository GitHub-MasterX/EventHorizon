#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/vps_field_common.sh
source "$SCRIPT_DIR/vps_field_common.sh"
vps_field_load_env

mode="${1:---once}"
[[ "$mode" == "--once" || "$mode" == "--loop" ]] || vps_field_die "usage: $0 [--once|--loop]"

capture_once() {
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
mkdir -p validation-output/snapshots
chmod 700 validation-output validation-output/snapshots
FIELD_PROJECT_NAME="$project_name" \
FIELD_VALIDATION_OUTPUT_DIR="$deploy_dir/validation-output/snapshots" \
    scripts/field_validation_snapshot.sh
REMOTE
}

if [[ "$mode" == "--once" ]]; then
    capture_once
    exit 0
fi

interval_seconds=$((SNAPSHOT_INTERVAL_HOURS * 3600))
printf 'Starting local snapshot loop: one remote aggregate snapshot every %s hour(s).\n' "$SNAPSHOT_INTERVAL_HOURS"
printf 'Press Ctrl-C to stop the loop. This does not install cron or systemd units on the VPS.\n'
trap 'printf "Snapshot loop stopped.\n"; exit 0' INT TERM
while :; do
    capture_once
    sleep "$interval_seconds"
done
