#!/usr/bin/env python3
"""EventHorizon deterministic deployment-smoke snapshot collector."""

from __future__ import annotations

import base64
import json
import math
import os
import re
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from pathlib import PurePosixPath


SCHEMA_VERSION = 1
PROTOCOLS = (("telnet", "Telnet", "telnet_pit"), ("mqtt", "MQTT", "mqtt_pit"))
SERVICES = (
    "cadvisor",
    "grafana",
    "mqtt_pit",
    "prometheus",
    "prometheus-exporter",
    "telnet_pit",
)
FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
RUN_ID = re.compile(r"^deploy-[0-9]{8}T[0-9]{6}Z-[a-z0-9]{6,32}$")
ALIAS = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
PROJECT = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")
PROMETHEUS_URL = re.compile(r"^http://127[.]0[.]0[.]1:[0-9]{1,5}$")
IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _utc_from_timestamp(value: float) -> str:
    return datetime.fromtimestamp(value, timezone.utc).isoformat().replace(
        "+00:00",
        "Z",
    )


def _decode_request(encoded: str) -> dict[str, object]:
    if len(encoded) > 128 * 1024:
        raise ValueError("request is too large")
    try:
        request = json.loads(base64.urlsafe_b64decode(encoded).decode("utf-8"))
    except (ValueError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("request is malformed") from error
    expected_keys = {
        "schema_version",
        "action",
        "run_id",
        "target_alias",
        "deployment_commit",
        "deploy_dir",
        "project_name",
        "expected_image_ids",
        "baseline_scrape_utc",
        "prometheus_url",
        "settle_timeout_seconds",
    }
    if not isinstance(request, dict) or set(request) != expected_keys:
        raise ValueError("request fields are unsupported")
    action = request["action"]
    if (
        request["schema_version"] != SCHEMA_VERSION
        or action not in {"BASELINE", "FINAL"}
        or not isinstance(request["run_id"], str)
        or RUN_ID.fullmatch(request["run_id"]) is None
        or not isinstance(request["target_alias"], str)
        or ALIAS.fullmatch(request["target_alias"]) is None
        or not isinstance(request["deployment_commit"], str)
        or FULL_SHA.fullmatch(request["deployment_commit"]) is None
        or not isinstance(request["project_name"], str)
        or PROJECT.fullmatch(request["project_name"]) is None
        or not isinstance(request["prometheus_url"], str)
        or PROMETHEUS_URL.fullmatch(request["prometheus_url"]) is None
        or type(request["settle_timeout_seconds"]) is not int
        or not 1 <= request["settle_timeout_seconds"] <= 120
    ):
        raise ValueError("request values are unsupported")
    deploy_dir = request["deploy_dir"]
    if not isinstance(deploy_dir, str):
        raise ValueError("deployment directory is unsupported")
    deploy_path = PurePosixPath(deploy_dir)
    unsafe_roots = {
        "/", "/bin", "/boot", "/dev", "/etc", "/home", "/lib",
        "/lib64", "/proc", "/root", "/run", "/sbin", "/sys",
        "/tmp", "/usr", "/var",
    }
    if (
        not deploy_path.is_absolute()
        or ".." in deploy_path.parts
        or str(deploy_path) != deploy_dir
        or deploy_dir in unsafe_roots
        or len(deploy_path.parts) < 3
    ):
        raise ValueError("deployment directory is unsupported")
    image_ids = request["expected_image_ids"]
    if (
        not isinstance(image_ids, dict)
        or set(image_ids) != set(SERVICES)
        or not all(
            isinstance(value, str) and IMAGE_ID.fullmatch(value)
            for value in image_ids.values()
        )
    ):
        raise ValueError("expected image identities are unsupported")
    baseline = request["baseline_scrape_utc"]
    if action == "BASELINE" and baseline is not None:
        raise ValueError("baseline action must not include a prior scrape")
    if action == "FINAL":
        if not isinstance(baseline, str) or _parse_utc(baseline) is None:
            raise ValueError("final action requires a prior scrape")
    port = int(request["prometheus_url"].rsplit(":", 1)[1])
    if not 1 <= port <= 65535:
        raise ValueError("Prometheus port is unsupported")
    return request


def _parse_utc(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def _command(*arguments: str) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment.update({"GIT_TERMINAL_PROMPT": "0", "LC_ALL": "C"})
    return subprocess.run(
        list(arguments),
        text=True,
        capture_output=True,
        check=False,
        timeout=20,
        env=environment,
    )


def _verify_checkout(request: dict[str, object]) -> None:
    completed = _command(
        "git",
        "-C",
        str(request["deploy_dir"]),
        "rev-parse",
        "HEAD",
    )
    if completed.returncode != 0 or completed.stdout.strip() != request["deployment_commit"]:
        raise RuntimeError("deployment checkout identity is invalid")


def _container_state(
    request: dict[str, object],
    service: str,
) -> dict[str, object]:
    listed = _command(
        "docker",
        "ps",
        "-aq",
        "--filter",
        f"label=com.docker.compose.project={request['project_name']}",
        "--filter",
        f"label=com.docker.compose.service={service}",
    )
    identifiers = [line for line in listed.stdout.splitlines() if line]
    if listed.returncode != 0 or len(identifiers) != 1:
        raise RuntimeError("managed service identity is invalid")
    inspected = _command("docker", "inspect", identifiers[0])
    try:
        documents = json.loads(inspected.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError("managed service state is invalid") from error
    if inspected.returncode != 0 or not isinstance(documents, list) or len(documents) != 1:
        raise RuntimeError("managed service state is invalid")
    document = documents[0]
    state = document.get("State") if isinstance(document, dict) else None
    if (
        not isinstance(state, dict)
        or state.get("Status") != "running"
        or type(document.get("RestartCount")) is not int
        or document["RestartCount"] < 0
        or type(state.get("OOMKilled")) is not bool
    ):
        raise RuntimeError("managed service state is invalid")
    expected_image = request["expected_image_ids"][service]
    return {
        "restart_count": document["RestartCount"],
        "oom_killed": state["OOMKilled"],
        "image_id_verified": document.get("Image") == expected_image,
    }


def _query_scalar(base_url: str, expression: str) -> float:
    query = urllib.parse.urlencode({"query": expression})
    with urllib.request.urlopen(
        f"{base_url}/api/v1/query?{query}",
        timeout=10,
    ) as response:
        payload = json.load(response)
    try:
        result = payload["data"]["result"]
        if payload["status"] != "success" or len(result) != 1:
            raise ValueError
        value = float(result[0]["value"][1])
    except (KeyError, TypeError, ValueError, IndexError) as error:
        raise RuntimeError("Prometheus returned malformed evidence") from error
    if not math.isfinite(value):
        raise RuntimeError("Prometheus returned non-finite evidence")
    return value


def _counter(base_url: str, expression: str) -> int:
    value = _query_scalar(base_url, f"({expression}) or vector(0)")
    try:
        decimal = Decimal(str(value))
    except InvalidOperation as error:
        raise RuntimeError("Prometheus counter is malformed") from error
    integral = decimal.to_integral_value()
    if decimal != integral or integral < 0:
        raise RuntimeError("Prometheus counter is malformed")
    return int(integral)


def _scrape_marker(base_url: str) -> float:
    return _query_scalar(
        base_url,
        'max(timestamp(total_connects{server=~"Telnet|MQTT"}))',
    )


def _capture_snapshot(request: dict[str, object], marker: float) -> dict[str, object]:
    base_url = str(request["prometheus_url"])
    protocols = []
    for protocol, server, service in PROTOCOLS:
        container = _container_state(request, service)
        snapshot = {
            "protocol": protocol,
            "connections": _counter(
                base_url,
                f'sum(total_connects{{server="{server}"}})',
            ),
            "completed_sessions": _counter(
                base_url,
                f'sum(eventhorizon_completed_sessions_total{{protocol="{protocol}"}})',
            ),
            "active_sessions": _counter(
                base_url,
                f'sum(current_connected_clients{{server="{server}"}})',
            ),
            "duration_count": _counter(
                base_url,
                f'sum(eventhorizon_session_duration_ms_count{{protocol="{protocol}"}})',
            ),
            "duration_inf": _counter(
                base_url,
                f'sum(eventhorizon_session_duration_ms_bucket{{protocol="{protocol}",le="+Inf"}})',
            ),
            "application_bytes_received": _counter(
                base_url,
                f'sum(eventhorizon_bytes_received_total{{protocol="{protocol}"}})',
            ),
            "application_bytes_sent": _counter(
                base_url,
                f'sum(eventhorizon_bytes_sent_total{{protocol="{protocol}"}})',
            ),
            **container,
        }
        for depth in range(4):
            snapshot[f"depth_{depth}"] = _counter(
                base_url,
                "sum(eventhorizon_session_interaction_depth_total"
                f'{{protocol="{protocol}",depth_level="{depth}"}})',
            )
        protocols.append(snapshot)
    return {
        "captured_utc": _utc_now(),
        "scrape_utc": _utc_from_timestamp(marker),
        "malformed_messages": _counter(
            base_url,
            "sum(eventhorizon_exporter_malformed_messages_total)",
        ),
        "protocols": protocols,
    }


def _result(
    request: dict[str, object],
    outcome: str,
    reason_code: str,
    snapshot: dict[str, object] | None,
) -> dict[str, object]:
    return {
        "schema_version": SCHEMA_VERSION,
        "action": request["action"],
        "run_id": request["run_id"],
        "target_alias": request["target_alias"],
        "deployment_commit": request["deployment_commit"],
        "result": outcome,
        "reason_code": reason_code,
        "snapshot": snapshot,
    }


def _run(request: dict[str, object]) -> dict[str, object]:
    _verify_checkout(request)
    base_url = str(request["prometheus_url"])
    if request["action"] == "BASELINE":
        not_before = _scrape_marker(base_url)
    else:
        baseline = _parse_utc(str(request["baseline_scrape_utc"]))
        assert baseline is not None
        not_before = max(baseline.timestamp(), _scrape_marker(base_url))
    deadline = time.monotonic() + int(request["settle_timeout_seconds"])
    latest: dict[str, object] | None = None
    while time.monotonic() <= deadline:
        marker_before = _scrape_marker(base_url)
        latest = _capture_snapshot(request, marker_before)
        marker_after = _scrape_marker(base_url)
        if marker_after != marker_before:
            time.sleep(0.2)
            continue
        latest["scrape_utc"] = _utc_from_timestamp(marker_after)
        active_zero = all(
            protocol["active_sessions"] == 0
            for protocol in latest["protocols"]
        )
        image_ids_match = all(
            protocol["image_id_verified"]
            for protocol in latest["protocols"]
        )
        if not image_ids_match:
            return _result(request, "ERROR", "RUNTIME_STATE_INVALID", latest)
        if marker_after > not_before and active_zero:
            return _result(request, "PASS", "SNAPSHOT_CAPTURED", latest)
        time.sleep(0.5)
    if request["action"] == "BASELINE":
        return _result(
            request,
            "BLOCKED",
            "ACTIVE_SESSIONS_DID_NOT_SETTLE",
            latest,
        )
    return _result(
        request,
        "INCONCLUSIVE",
        "FRESH_SCRAPE_UNAVAILABLE",
        latest,
    )


def main(arguments: list[str] | None = None) -> int:
    raw = sys.argv[1:] if arguments is None else arguments
    if raw == ["--help"]:
        print("usage: vps_field_remote_smoke.py <encoded-request>")
        return 0
    if len(raw) != 1:
        print("usage: vps_field_remote_smoke.py <encoded-request>", file=sys.stderr)
        return 2
    try:
        request = _decode_request(raw[0])
        result = _run(request)
    except Exception:
        return 5
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
