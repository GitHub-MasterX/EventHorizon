#!/usr/bin/env python3
"""Collect bounded EventHorizon runtime health and binding evidence."""

from __future__ import annotations

import base64
import concurrent.futures
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence


SCHEMA_VERSION = 1
EXPECTED_SERVICES = (
    "cadvisor",
    "grafana",
    "mqtt_pit",
    "prometheus",
    "prometheus-exporter",
    "telnet_pit",
)
EXPECTED_BINDINGS = {
    "cadvisor": (8080, 8081, "127.0.0.1", "LOOPBACK"),
    "grafana": (3000, 3000, "127.0.0.1", "LOOPBACK"),
    "mqtt_pit": (1883, 1883, "0.0.0.0", "PUBLIC"),
    "prometheus": (9090, 9090, "127.0.0.1", "LOOPBACK"),
    "prometheus-exporter": (9101, 9101, "127.0.0.1", "LOOPBACK"),
    "telnet_pit": (23, 23, "0.0.0.0", "PUBLIC"),
}
MANAGEMENT_ENDPOINTS = {
    "cadvisor": (8081, "http://127.0.0.1:8081/healthz"),
    "grafana": (3000, "http://127.0.0.1:3000/api/health"),
    "prometheus": (9090, "http://127.0.0.1:9090/-/ready"),
    "prometheus-exporter": (9101, "http://127.0.0.1:9101/metrics"),
}
EXPECTED_REQUEST_KEYS = {
    "schema_version",
    "action",
    "run_id",
    "target_alias",
    "deployment_commit",
    "deploy_dir",
    "project_name",
    "expected_image_ids",
}
COMPOSE_FILES = (
    "docker-compose.yml",
    "docker-compose.cost.yml",
    "docker-compose.field.yml",
)


@dataclass(frozen=True)
class RuntimeFailure(RuntimeError):
    outcome: str
    blocker: str


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _decode_request(encoded: str) -> dict[str, Any]:
    if len(encoded) > 128 * 1024:
        raise ValueError("request is too large")
    document = json.loads(base64.urlsafe_b64decode(encoded).decode("utf-8"))
    if not isinstance(document, dict) or set(document) != EXPECTED_REQUEST_KEYS:
        raise ValueError("request fields are invalid")
    deploy_dir = document["deploy_dir"]
    deploy_path = Path(deploy_dir) if isinstance(deploy_dir, str) else Path("/")
    image_ids = document["expected_image_ids"]
    if (
        document["schema_version"] != SCHEMA_VERSION
        or document["action"] not in {"VERIFY", "STOP"}
        or not isinstance(document["run_id"], str)
        or re.fullmatch(
            r"deploy-[0-9]{8}T[0-9]{6}Z-[a-z0-9]{6,32}",
            document["run_id"],
        )
        is None
        or not isinstance(document["target_alias"], str)
        or re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}",
            document["target_alias"],
        )
        is None
        or not isinstance(document["deployment_commit"], str)
        or re.fullmatch(r"[0-9a-f]{40}", document["deployment_commit"]) is None
        or not isinstance(deploy_dir, str)
        or not deploy_path.is_absolute()
        or ".." in deploy_path.parts
        or len(deploy_path.parts) < 3
        or deploy_path in {Path("/"), Path("/home"), Path("/root"), Path("/srv")}
        or not isinstance(document["project_name"], str)
        or re.fullmatch(
            r"[a-z0-9][a-z0-9_-]{0,62}",
            document["project_name"],
        )
        is None
        or not isinstance(image_ids, dict)
        or (
            document["action"] == "VERIFY"
            and (
                set(image_ids) != set(EXPECTED_SERVICES)
                or not all(
                    isinstance(image_id, str)
                    and re.fullmatch(r"sha256:[0-9a-f]{64}", image_id)
                    is not None
                    for image_id in image_ids.values()
                )
            )
        )
        or (document["action"] == "STOP" and image_ids)
    ):
        raise ValueError("request values are invalid")
    return document


def _run(
    arguments: Sequence[str],
    *,
    cwd: Path | None = None,
    timeout: int = 15,
) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment.update({"GIT_TERMINAL_PROMPT": "0", "LC_ALL": "C"})
    try:
        return subprocess.run(
            list(arguments),
            cwd=cwd,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
            timeout=timeout,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as error:
        raise RuntimeFailure(
            "ERROR",
            "Required runtime verification tooling malfunctioned.",
        ) from error


def _require(
    completed: subprocess.CompletedProcess[str],
    blocker: str,
) -> str:
    if completed.returncode != 0:
        raise RuntimeFailure("ERROR", blocker)
    if len(completed.stdout.encode("utf-8")) > 512 * 1024:
        raise RuntimeFailure(
            "ERROR",
            "Runtime verification tooling returned excessive output.",
        )
    return completed.stdout


def _compose_command(request: dict[str, Any]) -> tuple[str, ...]:
    command = ["docker", "compose", "-p", request["project_name"]]
    for compose_file in COMPOSE_FILES:
        command.extend(("-f", compose_file))
    return tuple(command)


def _checkout_is_exact(request: dict[str, Any], deploy_dir: Path) -> None:
    if (
        deploy_dir.is_symlink()
        or not deploy_dir.is_dir()
        or not (deploy_dir / ".git").is_dir()
    ):
        raise RuntimeFailure(
            "BLOCKED",
            "Runtime verification requires the managed deployment checkout.",
        )
    head = _require(
        _run(("git", "-C", str(deploy_dir), "rev-parse", "HEAD")),
        "Runtime checkout identity could not be inspected.",
    ).strip()
    status = _require(
        _run(
            (
                "git",
                "-C",
                str(deploy_dir),
                "status",
                "--porcelain",
                "--untracked-files=normal",
            )
        ),
        "Runtime checkout cleanliness could not be inspected.",
    )
    if head != request["deployment_commit"] or status:
        raise RuntimeFailure(
            "BLOCKED",
            "Runtime checkout no longer matches the exact deployment commit.",
        )


def _inspect_service(
    request: dict[str, Any],
    deploy_dir: Path,
    compose: Sequence[str],
    service: str,
) -> tuple[dict[str, object], dict[str, object]]:
    container_id = _require(
        _run(
            (*compose, "ps", "--all", "-q", service),
            cwd=deploy_dir,
        ),
        "Runtime service identity could not be collected.",
    ).strip()
    if not container_id:
        return (
            {
                "name": service,
                "state": "UNKNOWN",
                "health": "UNKNOWN",
                "restart_count": 0,
                "oom_killed": False,
                "image_id_verified": False,
            },
            {
                "service": service,
                "container_port": EXPECTED_BINDINGS[service][0],
                "host_port": EXPECTED_BINDINGS[service][1],
                "scope": EXPECTED_BINDINGS[service][3],
                "result": "FAIL",
            },
        )
    raw_inspect = _require(
        _run(
            ("docker", "inspect", "--format", "{{json .}}", container_id),
        ),
        "Runtime container state could not be collected.",
    )
    try:
        inspected = json.loads(raw_inspect)
    except json.JSONDecodeError as error:
        raise RuntimeFailure(
            "ERROR",
            "Docker returned malformed runtime state.",
        ) from error
    if not isinstance(inspected, dict):
        raise RuntimeFailure("ERROR", "Docker returned malformed runtime state.")

    config = inspected.get("Config")
    state = inspected.get("State")
    network = inspected.get("NetworkSettings")
    labels = config.get("Labels") if isinstance(config, dict) else None
    if (
        not isinstance(labels, dict)
        or labels.get("com.docker.compose.project")
        != request["project_name"]
        or labels.get("com.docker.compose.service") != service
        or not isinstance(state, dict)
        or not isinstance(network, dict)
    ):
        raise RuntimeFailure(
            "FAIL",
            "Runtime container identity does not match the managed project.",
        )

    raw_status = state.get("Status")
    status = (
        raw_status.upper()
        if isinstance(raw_status, str)
        and raw_status.upper() in {"RUNNING", "STOPPED", "EXITED"}
        else "UNKNOWN"
    )
    raw_health = state.get("Health")
    if isinstance(raw_health, dict) and isinstance(
        raw_health.get("Status"),
        str,
    ):
        health = raw_health["Status"].upper()
        if health not in {"HEALTHY", "UNHEALTHY", "STARTING"}:
            health = "UNKNOWN"
    else:
        health = "NOT_CONFIGURED"
    restart_count = inspected.get("RestartCount")
    oom_killed = state.get("OOMKilled")
    if (
        type(restart_count) is not int
        or restart_count < 0
        or type(oom_killed) is not bool
    ):
        raise RuntimeFailure("ERROR", "Docker returned malformed runtime state.")
    image_verified = (
        inspected.get("Image") == request["expected_image_ids"][service]
    )

    container_port, host_port, host_ip, scope = EXPECTED_BINDINGS[service]
    ports = network.get("Ports")
    raw_bindings = (
        ports.get(f"{container_port}/tcp")
        if isinstance(ports, dict)
        else None
    )
    binding_pairs: set[tuple[str, str]] = set()
    bindings_well_formed = (
        isinstance(raw_bindings, list)
        and 1 <= len(raw_bindings) <= 2
    )
    if bindings_well_formed:
        for raw_binding in raw_bindings:
            if (
                not isinstance(raw_binding, dict)
                or set(raw_binding) != {"HostIp", "HostPort"}
                or not isinstance(raw_binding["HostIp"], str)
                or not isinstance(raw_binding["HostPort"], str)
            ):
                bindings_well_formed = False
                break
            binding_pairs.add(
                (
                    raw_binding["HostIp"],
                    raw_binding["HostPort"],
                )
            )
    expected_pair = {(host_ip, str(host_port))}
    allowed_pairs = (
        (expected_pair, expected_pair | {("::", str(host_port))})
        if scope == "PUBLIC"
        else (expected_pair,)
    )
    binding_passed = (
        bindings_well_formed
        and len(binding_pairs) == len(raw_bindings)
        and binding_pairs in allowed_pairs
    )
    return (
        {
            "name": service,
            "state": status,
            "health": health,
            "restart_count": restart_count,
            "oom_killed": oom_killed,
            "image_id_verified": image_verified,
        },
        {
            "service": service,
            "container_port": container_port,
            "host_port": host_port,
            "scope": scope,
            "result": "PASS" if binding_passed else "FAIL",
        },
    )


def _collect_once(request: dict[str, Any]) -> dict[str, object]:
    deploy_dir = Path(request["deploy_dir"])
    _checkout_is_exact(request, deploy_dir)
    compose = _compose_command(request)
    services: list[dict[str, object]] = []
    bindings: list[dict[str, object]] = []
    for service in EXPECTED_SERVICES:
        service_state, binding = _inspect_service(
            request,
            deploy_dir,
            compose,
            service,
        )
        services.append(service_state)
        bindings.append(binding)

    def check_endpoint(
        item: tuple[str, tuple[int, str]],
    ) -> dict[str, object]:
        service, (port, url) = item
        completed = _run(
            (
                "curl",
                "--fail",
                "--silent",
                "--show-error",
                "--max-time",
                "5",
                url,
            ),
            timeout=10,
        )
        return {
            "service": service,
            "port": port,
            "result": (
                "READY" if completed.returncode == 0 else "NOT_READY"
            ),
        }

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=len(MANAGEMENT_ENDPOINTS)
    ) as executor:
        management_endpoints = list(
            executor.map(
                check_endpoint,
                MANAGEMENT_ENDPOINTS.items(),
            )
        )

    services_pass = all(
        service["state"] == "RUNNING"
        and service["health"] in {"HEALTHY", "NOT_CONFIGURED"}
        and service["restart_count"] == 0
        and service["oom_killed"] is False
        and service["image_id_verified"] is True
        for service in services
    )
    bindings_pass = all(
        binding["result"] == "PASS" for binding in bindings
    )
    endpoints_pass = all(
        endpoint["result"] == "READY"
        for endpoint in management_endpoints
    )
    passed = services_pass and bindings_pass and endpoints_pass
    return {
        "schema_version": SCHEMA_VERSION,
        "run_id": request["run_id"],
        "target_alias": request["target_alias"],
        "deployment_commit": request["deployment_commit"],
        "checked_utc": _utc_now(),
        "result": "PASS" if passed else "FAIL",
        "blocker": (
            None
            if passed
            else "Runtime health or supported binding validation failed."
        ),
        "field_services_running": all(
            service["state"] == "RUNNING" for service in services
        ),
        "services": services,
        "bindings": bindings,
        "management_endpoints": management_endpoints,
    }


def _is_settling(evidence: dict[str, object]) -> bool:
    services = evidence["services"]
    bindings = evidence["bindings"]
    endpoints = evidence["management_endpoints"]
    assert isinstance(services, list)
    assert isinstance(bindings, list)
    assert isinstance(endpoints, list)
    return (
        all(
            service["state"] == "RUNNING"
            and service["health"]
            in {"HEALTHY", "NOT_CONFIGURED", "STARTING"}
            and service["restart_count"] == 0
            and service["oom_killed"] is False
            and service["image_id_verified"] is True
            for service in services
        )
        and all(binding["result"] == "PASS" for binding in bindings)
        and (
            any(
                service["health"] == "STARTING"
                for service in services
            )
            or any(
                endpoint["result"] == "NOT_READY"
                for endpoint in endpoints
            )
        )
    )


def _collect(request: dict[str, Any]) -> dict[str, object]:
    attempts = 12
    for attempt in range(attempts):
        evidence = _collect_once(request)
        if evidence["result"] == "PASS":
            return evidence
        if not _is_settling(evidence) or attempt == attempts - 1:
            return evidence
        time.sleep(5)
    raise AssertionError("bounded runtime verification loop exhausted")


def _stop(request: dict[str, Any]) -> dict[str, object]:
    deploy_dir = Path(request["deploy_dir"])
    _checkout_is_exact(request, deploy_dir)
    rows_output = _require(
        _run(
            (
                "docker",
                "ps",
                "-a",
                "--filter",
                (
                    "label=com.docker.compose.project="
                    + request["project_name"]
                ),
                "--format",
                (
                    '{{.ID}}\t{{.Label "com.docker.compose.project"}}'
                    '\t{{.Label "com.docker.compose.service"}}'
                ),
            )
        ),
        "Managed field service identities could not be collected for cleanup.",
    )
    rows: list[tuple[str, str, str]] = []
    for line in rows_output.splitlines():
        fields = line.split("\t")
        if len(fields) != 3 or not all(fields):
            raise RuntimeFailure(
                "ERROR",
                "Docker returned malformed cleanup identities.",
            )
        rows.append((fields[0], fields[1], fields[2]))
    if (
        len(rows) != len(EXPECTED_SERVICES)
        or {row[1] for row in rows} != {request["project_name"]}
        or {row[2] for row in rows} != set(EXPECTED_SERVICES)
    ):
        raise RuntimeFailure(
            "ERROR",
            "Cleanup could not prove the exact managed field service set.",
        )
    _require(
        _run(("docker", "stop", *(row[0] for row in rows)), timeout=180),
        "Managed field services could not be stopped.",
    )
    running = _require(
        _run(
            (
                "docker",
                "ps",
                "--filter",
                (
                    "label=com.docker.compose.project="
                    + request["project_name"]
                ),
                "-q",
            )
        ),
        "Managed field-service cleanup could not be verified.",
    )
    if running.strip():
        raise RuntimeFailure(
            "ERROR",
            "Managed field services remain running after cleanup.",
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "action": "STOP",
        "run_id": request["run_id"],
        "target_alias": request["target_alias"],
        "deployment_commit": request["deployment_commit"],
        "result": "PASS",
        "blocker": None,
        "field_services_running": False,
    }


def _response_for_failure(
    request: dict[str, Any],
    failure: RuntimeFailure,
) -> dict[str, object]:
    return {
        "schema_version": SCHEMA_VERSION,
        "run_id": request["run_id"],
        "target_alias": request["target_alias"],
        "deployment_commit": request["deployment_commit"],
        "checked_utc": _utc_now(),
        "result": failure.outcome,
        "blocker": failure.blocker,
        "field_services_running": True,
        "services": [],
        "bindings": [],
        "management_endpoints": [],
    }


def main(arguments: Sequence[str] | None = None) -> int:
    raw_arguments = list(sys.argv[1:] if arguments is None else arguments)
    if raw_arguments in (["-h"], ["--help"]):
        print("usage: vps_field_remote_runtime.py <encoded-request>")
        print(
            "Collect bounded exact-commit runtime health and binding evidence."
        )
        return 0
    if len(raw_arguments) != 1:
        print("remote runtime verification request is required", file=sys.stderr)
        return 2
    try:
        request = _decode_request(raw_arguments[0])
    except (ValueError, UnicodeError, json.JSONDecodeError):
        print("remote runtime verification request is invalid", file=sys.stderr)
        return 2
    try:
        response = (
            _collect(request)
            if request["action"] == "VERIFY"
            else _stop(request)
        )
    except RuntimeFailure as failure:
        if request["action"] == "VERIFY":
            response = _response_for_failure(request, failure)
        else:
            response = {
                "schema_version": SCHEMA_VERSION,
                "action": "STOP",
                "run_id": request["run_id"],
                "target_alias": request["target_alias"],
                "deployment_commit": request["deployment_commit"],
                "result": failure.outcome,
                "blocker": failure.blocker,
                "field_services_running": True,
            }
    except BaseException:
        failure = RuntimeFailure(
            "ERROR",
            "Remote runtime verification program malfunctioned.",
        )
        response = (
            _response_for_failure(request, failure)
            if request["action"] == "VERIFY"
            else {
                "schema_version": SCHEMA_VERSION,
                "action": "STOP",
                "run_id": request["run_id"],
                "target_alias": request["target_alias"],
                "deployment_commit": request["deployment_commit"],
                "result": failure.outcome,
                "blocker": failure.blocker,
                "field_services_running": True,
            }
        )
    print(json.dumps(response, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
