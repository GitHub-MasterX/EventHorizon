#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
FIELD_PROJECT_NAME="${FIELD_PROJECT_NAME:-eventhorizon-field}"
OUTPUT_DIR="${FIELD_VALIDATION_OUTPUT_DIR:-$REPO_ROOT/validation-output}"
UTC_STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
STOP_REPORT="$OUTPUT_DIR/field-stop-$UTC_STAMP.txt"
umask 077
mkdir -p "$OUTPUT_DIR"

cd "$REPO_ROOT"
COMPOSE=(docker compose -p "$FIELD_PROJECT_NAME" -f docker-compose.yml -f docker-compose.cost.yml -f docker-compose.field.yml)

final_snapshot="$(FIELD_PROJECT_NAME="$FIELD_PROJECT_NAME" FIELD_VALIDATION_OUTPUT_DIR="$OUTPUT_DIR" "$SCRIPT_DIR/field_validation_snapshot.sh")"

{
    printf 'EventHorizon field-validation stop report\n'
    printf 'stop_requested_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'final_snapshot=%s\n' "$final_snapshot"
    printf '\n[state before stop]\n'
    "${COMPOSE[@]}" ps -a || true
} >"$STOP_REPORT"

"${COMPOSE[@]}" stop

{
    printf '\n[state after stop]\n'
    "${COMPOSE[@]}" ps -a || true
    printf '\nPrometheus and Grafana volumes were preserved; no evidence or runtime volume was deleted.\n'
} >>"$STOP_REPORT"

printf '%s\n' "$STOP_REPORT"
