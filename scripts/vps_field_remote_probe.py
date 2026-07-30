#!/usr/bin/env python3
"""EventHorizon remote preflight probe executed through the deployment controller."""

from __future__ import annotations

import base64
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 1
REQUIRED_PORTS = (23, 1883, 3000, 8081, 9090, 9101)
EXPECTED_REQUEST_KEYS = {
    "schema_version",
    "target_alias",
    "deployment_commit",
    "deploy_dir",
    "project_name",
    "trusted_repository",
    "memory_limit",
    "reference_epoch",
}


def _decode_request(encoded: str) -> dict[str, Any]:
    if len(encoded) > 64 * 1024:
        raise ValueError("request is too large")
    document = json.loads(base64.urlsafe_b64decode(encoded).decode("utf-8"))
    if not isinstance(document, dict) or set(document) != EXPECTED_REQUEST_KEYS:
        raise ValueError("request fields are invalid")
    if (
        document["schema_version"] != SCHEMA_VERSION
        or not isinstance(document["target_alias"], str)
        or re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}",
            document["target_alias"],
        )
        is None
        or not isinstance(document["deployment_commit"], str)
        or re.fullmatch(r"[0-9a-f]{40}", document["deployment_commit"]) is None
        or not isinstance(document["deploy_dir"], str)
        or not Path(document["deploy_dir"]).is_absolute()
        or not isinstance(document["project_name"], str)
        or re.fullmatch(
            r"[a-z0-9][a-z0-9_-]{0,62}",
            document["project_name"],
        )
        is None
        or document["trusted_repository"] != "honeynet/EventHorizon"
        or (
            document["memory_limit"] is not None
            and not isinstance(document["memory_limit"], str)
        )
        or type(document["reference_epoch"]) is not int
    ):
        raise ValueError("request values are invalid")
    return document


def _command(*arguments: str) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment.update({"GIT_TERMINAL_PROMPT": "0", "LC_ALL": "C"})
    try:
        return subprocess.run(
            list(arguments),
            text=True,
            capture_output=True,
            check=False,
            env=environment,
            timeout=10,
        )
    except FileNotFoundError:
        return subprocess.CompletedProcess(
            args=list(arguments),
            returncode=127,
            stdout="",
            stderr="",
        )


def _nearest_existing_directory(path: Path) -> Path:
    candidate = path
    while not candidate.exists():
        if candidate.parent == candidate:
            return Path("/")
        candidate = candidate.parent
    return candidate if candidate.is_dir() else candidate.parent


def _available_disk_bytes(path: Path) -> int:
    completed = _command("df", "-Pk", str(_nearest_existing_directory(path)))
    if completed.returncode != 0:
        return 0
    lines = completed.stdout.splitlines()
    if len(lines) < 2:
        return 0
    try:
        return int(lines[-1].split()[3], 10) * 1024
    except (ValueError, IndexError):
        return 0


def _available_memory_mib() -> int:
    try:
        for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
            if line.startswith("MemAvailable:"):
                return int(line.split()[1], 10) // 1024
    except (OSError, ValueError, IndexError):
        return 0
    return 0


def _cgroup_memory_available() -> bool:
    try:
        controllers = Path(
            "/sys/fs/cgroup/cgroup.controllers"
        ).read_text(encoding="utf-8").split()
    except OSError:
        return False
    return (
        "memory" in controllers
        and Path("/sys/fs/cgroup/memory.current").is_file()
    )


def _listener_ports(output: str) -> set[int]:
    listeners: set[int] = set()
    for line in output.splitlines():
        for match in re.finditer(r":([0-9]{1,5})(?:\s|$)", line):
            port = int(match.group(1), 10)
            if port in REQUIRED_PORTS:
                listeners.add(port)
    return listeners


def _published_ports(value: str) -> set[int]:
    return {
        int(match.group(1), 10)
        for match in re.finditer(r":([0-9]{1,5})->", value)
        if int(match.group(1), 10) in REQUIRED_PORTS
    }


def _trusted_origin_matches(origin: str, repository: str) -> bool:
    return origin.removesuffix(".git") in {
        f"git@github.com:{repository}",
        f"https://github.com/{repository}",
        f"ssh://git@github.com/{repository}",
    }


def _read_bounded_json(path: Path) -> dict[str, Any] | None:
    try:
        if path.stat().st_size > 256 * 1024:
            return None
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    return document if isinstance(document, dict) else None


def _collect(request: dict[str, Any]) -> dict[str, object]:
    checks: list[dict[str, str]] = []

    def record(check_id: str, status: str, summary: str) -> None:
        checks.append(
            {
                "id": check_id,
                "status": status,
                "summary": summary,
            }
        )

    operating_system = _command("uname", "-s")
    record(
        "operating_system",
        "PASS"
        if operating_system.returncode == 0
        and operating_system.stdout.strip() == "Linux"
        else "BLOCKER",
        (
            "Authorized VPS runs Linux."
            if operating_system.returncode == 0
            and operating_system.stdout.strip() == "Linux"
            else "Authorized VPS must run Linux."
        ),
    )

    architecture = _command("uname", "-m")
    supported_architecture = (
        architecture.returncode == 0
        and architecture.stdout.strip() in {"x86_64", "amd64"}
    )
    record(
        "architecture",
        "PASS" if supported_architecture else "BLOCKER",
        (
            "Authorized VPS matches the supported linux/amd64 field platform."
            if supported_architecture
            else "Authorized VPS must match the linux/amd64 field platform."
        ),
    )

    cpu = _command("getconf", "_NPROCESSORS_ONLN")
    try:
        cpu_count = int(cpu.stdout.strip(), 10) if cpu.returncode == 0 else 0
    except ValueError:
        cpu_count = 0
    record(
        "cpu_capacity",
        "PASS" if cpu_count >= 2 else "BLOCKER",
        (
            "Authorized VPS has at least two logical CPUs."
            if cpu_count >= 2
            else "Authorized VPS requires at least two logical CPUs."
        ),
    )

    memory_mib = _available_memory_mib()
    record(
        "memory_capacity",
        "PASS" if memory_mib >= 1024 else "BLOCKER",
        (
            "Authorized VPS has at least 1024 MiB available memory."
            if memory_mib >= 1024
            else "Authorized VPS requires at least 1024 MiB available memory."
        ),
    )

    deploy_dir = Path(request["deploy_dir"])
    available_disk = _available_disk_bytes(deploy_dir)
    record(
        "disk_capacity",
        "PASS" if available_disk >= 5 * 1024**3 else "BLOCKER",
        (
            "Authorized VPS has at least 5 GiB available disk."
            if available_disk >= 5 * 1024**3
            else "Authorized VPS requires at least 5 GiB available disk."
        ),
    )

    now = datetime.now(timezone.utc)
    clock_delta = abs(int(now.timestamp()) - request["reference_epoch"])
    record(
        "clock",
        "PASS" if clock_delta <= 300 else "BLOCKER",
        (
            "Authorized VPS clock is within the five-minute deployment bound."
            if clock_delta <= 300
            else "Authorized VPS clock exceeds the five-minute deployment bound."
        ),
    )

    required_commands = (
        (
            "docker_engine",
            ("docker", "info", "--format", "{{.ServerVersion}}"),
            "Docker Engine is reachable.",
            "Docker Engine must be installed and reachable.",
        ),
        (
            "docker_compose",
            ("docker", "compose", "version", "--short"),
            "Docker Compose is available.",
            "Docker Compose must be available.",
        ),
        (
            "git",
            ("git", "--version"),
            "Git is available.",
            "Git must be available.",
        ),
        (
            "curl",
            ("curl", "--version"),
            "curl is available.",
            "curl must be available.",
        ),
        (
            "socket_inspection",
            ("ss", "--version"),
            "Socket inspection is available.",
            "The ss socket-inspection utility must be available.",
        ),
    )
    for check_id, arguments, pass_summary, fail_summary in required_commands:
        completed = _command(*arguments)
        record(
            check_id,
            "PASS" if completed.returncode == 0 else "BLOCKER",
            pass_summary if completed.returncode == 0 else fail_summary,
        )

    memory_available = _cgroup_memory_available()
    if request["memory_limit"] is not None:
        record(
            "memory_controller",
            "PASS" if memory_available else "BLOCKER",
            (
                "The requested memory limit is supported."
                if memory_available
                else "The requested memory limit requires cgroup-v2 memory support."
            ),
        )
    else:
        record(
            "memory_controller",
            "PASS" if memory_available else "WARNING",
            (
                "cgroup-v2 memory accounting is available."
                if memory_available
                else "No memory limit is configured; memory accounting is unavailable."
            ),
        )

    containers = _command(
        "docker",
        "ps",
        "-a",
        "--format",
        (
            '{{.Names}}\t{{.Label "com.docker.compose.project"}}'
            "\t{{.Ports}}"
        ),
    )
    container_rows: list[tuple[str, str, str]] | None = []
    if containers.returncode != 0:
        container_rows = None
    else:
        for line in containers.stdout.rstrip("\n").splitlines():
            if not line:
                continue
            fields = line.split("\t", 2)
            if len(fields) != 3:
                container_rows = None
                break
            container_rows.append((fields[0], fields[1], fields[2]))

    projects = _command("docker", "compose", "ls", "--format", "json")
    try:
        project_documents = (
            json.loads(projects.stdout) if projects.returncode == 0 else None
        )
    except json.JSONDecodeError:
        project_documents = None
    project_names: set[str] | None = None
    if isinstance(project_documents, list):
        project_names = set()
        for project in project_documents:
            if not isinstance(project, dict) or not isinstance(
                project.get("Name"),
                str,
            ):
                project_names = None
                break
            project_names.add(project["Name"])

    sockets = _command("ss", "-H", "-ltn")
    occupied_ports = (
        _listener_ports(sockets.stdout)
        if sockets.returncode == 0
        else set(REQUIRED_PORTS)
    )

    deployment_directory_is_symlink = deploy_dir.is_symlink()
    initial_directory = (
        not deployment_directory_is_symlink
        and (
            not deploy_dir.exists()
            or (deploy_dir.is_dir() and not any(deploy_dir.iterdir()))
        )
    )
    managed_directory = (
        not deployment_directory_is_symlink
        and deploy_dir.is_dir()
        and (deploy_dir / ".git").is_dir()
    )
    if initial_directory:
        starting_state = "INITIAL_DEPLOYMENT"
        record(
            "deployment_directory",
            "PASS",
            "Deployment directory is absent or empty.",
        )
        no_containers = container_rows == []
        record(
            "container_state",
            "PASS" if no_containers else "BLOCKER",
            (
                "No conflicting containers exist."
                if no_containers
                else "Initial deployment requires no existing containers."
            ),
        )
        no_projects = project_names == set()
        record(
            "compose_state",
            "PASS" if no_projects else "BLOCKER",
            (
                "No conflicting Compose projects exist."
                if no_projects
                else "Initial deployment requires no existing Compose projects."
            ),
        )
        record(
            "required_ports",
            "PASS" if not occupied_ports else "BLOCKER",
            (
                "Required field and management ports are available."
                if not occupied_ports
                else "One or more required ports are already in use."
            ),
        )
    elif managed_directory:
        starting_state = "MANAGED_REDEPLOYMENT"
        project_name = request["project_name"]

        origin = _command(
            "git",
            "-C",
            str(deploy_dir),
            "remote",
            "get-url",
            "origin",
        )
        trusted_origin = (
            origin.returncode == 0
            and _trusted_origin_matches(
                origin.stdout.strip(),
                request["trusted_repository"],
            )
        )
        record(
            "repository_origin",
            "PASS" if trusted_origin else "BLOCKER",
            (
                "Managed checkout uses the trusted repository."
                if trusted_origin
                else "Managed checkout must use the trusted repository."
            ),
        )

        status = _command(
            "git",
            "-C",
            str(deploy_dir),
            "status",
            "--porcelain",
            "--untracked-files=normal",
        )
        clean_checkout = status.returncode == 0 and not status.stdout
        record(
            "repository_cleanliness",
            "PASS" if clean_checkout else "BLOCKER",
            (
                "Managed checkout is clean."
                if clean_checkout
                else "Managed checkout must be clean."
            ),
        )

        head = _command(
            "git",
            "-C",
            str(deploy_dir),
            "rev-parse",
            "HEAD",
        )
        current_head = (
            head.stdout.strip()
            if head.returncode == 0
            and re.fullmatch(r"[0-9a-f]{40}", head.stdout.strip())
            else None
        )

        manifest = None
        for manifest_name in (
            "deployment-manifest.json",
            "deployment_manifest.json",
        ):
            candidate = deploy_dir / "validation-output" / manifest_name
            if candidate.is_file():
                manifest = _read_bounded_json(candidate)
                break
        prior_evidence_matches = (
            manifest is not None
            and current_head is not None
            and manifest.get("repository_commit") == current_head
            and manifest.get("compose_project_name") == project_name
        )
        record(
            "prior_deployment_evidence",
            "PASS" if prior_evidence_matches else "BLOCKER",
            (
                "Prior deployment evidence reconciles with the managed checkout."
                if prior_evidence_matches
                else "Managed redeployment requires matching prior deployment evidence."
            ),
        )

        matching_containers = (
            container_rows is not None
            and bool(container_rows)
            and all(row[1] == project_name for row in container_rows)
        )
        record(
            "container_state",
            "PASS" if matching_containers else "BLOCKER",
            (
                "Only the evidenced EventHorizon containers exist."
                if matching_containers
                else "Managed redeployment permits only the matching EventHorizon containers."
            ),
        )

        matching_project = project_names == {project_name}
        record(
            "compose_state",
            "PASS" if matching_project else "BLOCKER",
            (
                "Only the evidenced EventHorizon Compose project exists."
                if matching_project
                else "Managed redeployment permits only the matching Compose project."
            ),
        )

        volumes = _command(
            "docker",
            "volume",
            "ls",
            "--filter",
            f"label=com.docker.compose.project={project_name}",
            "--format",
            "{{.Name}}",
        )
        volume_names = (
            set(volumes.stdout.split())
            if volumes.returncode == 0
            else set()
        )
        expected_volumes = {
            f"{project_name}_prometheus-data",
            f"{project_name}_grafana-storage",
            f"{project_name}_tarpit-sock",
        }
        volumes_reconcile = volume_names == expected_volumes
        record(
            "volume_state",
            "PASS" if volumes_reconcile else "BLOCKER",
            (
                "Managed EventHorizon volumes are present."
                if volumes_reconcile
                else "Managed redeployment requires the evidenced EventHorizon volumes."
            ),
        )

        project_ports = (
            set().union(
                *(_published_ports(row[2]) for row in container_rows)
            )
            if container_rows
            else set()
        )
        ports_reconcile = occupied_ports.issubset(project_ports)
        record(
            "required_ports",
            "PASS" if ports_reconcile else "BLOCKER",
            (
                "Existing required listeners belong to the managed project."
                if ports_reconcile
                else "A required port conflicts with the managed project."
            ),
        )

        observation_path = (
            deploy_dir / "validation-output" / "observation_window.json"
        )
        observation = (
            _read_bounded_json(observation_path)
            if observation_path.exists()
            else {}
        )
        observation_closed = (
            observation is not None
            and (
                not observation
                or isinstance(observation.get("observation_end_utc"), str)
            )
        )
        record(
            "public_observation",
            "PASS" if observation_closed else "BLOCKER",
            (
                "No public-observation window is active."
                if observation_closed
                else "Managed redeployment is blocked during public observation."
            ),
        )
    else:
        starting_state = "UNSUPPORTED"
        record(
            "deployment_directory",
            "BLOCKER",
            "Deployment directory contains unmanaged state.",
        )
    result = (
        "BLOCKED"
        if any(check["status"] == "BLOCKER" for check in checks)
        else "PASS"
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "target_alias": request["target_alias"],
        "deployment_commit": request["deployment_commit"],
        "checked_utc": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "starting_state": starting_state,
        "result": result,
        "checks": checks,
    }


def main(arguments: list[str] | None = None) -> int:
    raw_arguments = list(sys.argv[1:] if arguments is None else arguments)
    if raw_arguments == ["--help"]:
        print(
            "usage: vps_field_remote_probe.py <encoded-request>\n\n"
            "Collect bounded, read-only authorized-VPS preflight evidence."
        )
        return 0
    if len(raw_arguments) != 1:
        print("remote preflight probe requires a controller request", file=sys.stderr)
        return 2
    try:
        request = _decode_request(raw_arguments[0])
        evidence = _collect(request)
    except (
        OSError,
        UnicodeError,
        ValueError,
        json.JSONDecodeError,
        subprocess.SubprocessError,
    ):
        print("remote preflight probe could not collect bounded evidence", file=sys.stderr)
        return 2
    print(json.dumps(evidence, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
