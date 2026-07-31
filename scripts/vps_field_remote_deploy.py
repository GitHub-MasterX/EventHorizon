#!/usr/bin/env python3
"""EventHorizon exact-source remote deployment executed through the controller."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Callable, Sequence


SCHEMA_VERSION = 1
TRUSTED_REPOSITORY = "honeynet/EventHorizon"
TRUSTED_REPOSITORY_URL = "https://github.com/honeynet/EventHorizon.git"
APPROVED_BRANCH = "GSoC_2026"
PLATFORM = "linux/amd64"
EXPECTED_COMPOSE_FILES = (
    "docker-compose.yml",
    "docker-compose.cost.yml",
    "docker-compose.field.yml",
)
EXPECTED_SERVICES = (
    "cadvisor",
    "grafana",
    "mqtt_pit",
    "prometheus",
    "prometheus-exporter",
    "telnet_pit",
)
EXPECTED_REQUEST_KEYS = {
    "schema_version",
    "run_id",
    "target_alias",
    "deployment_commit",
    "deploy_dir",
    "project_name",
    "trusted_repository",
    "approved_branch",
    "starting_state",
    "managed_checkout_commit",
    "prior_evidence_commit",
    "interrupted_redeployment",
    "compose_files",
    "cpu_limit",
    "memory_limit",
}


@dataclass(frozen=True)
class DeploymentFailure(RuntimeError):
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
    memory_limit = document["memory_limit"]
    managed_checkout_commit = document["managed_checkout_commit"]
    prior_evidence_commit = document["prior_evidence_commit"]
    interrupted_redeployment = document["interrupted_redeployment"]
    if (
        document["schema_version"] != SCHEMA_VERSION
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
        or document["trusted_repository"] != TRUSTED_REPOSITORY
        or document["approved_branch"] != APPROVED_BRANCH
        or document["starting_state"]
        not in {"INITIAL_DEPLOYMENT", "MANAGED_REDEPLOYMENT"}
        or type(interrupted_redeployment) is not bool
        or (
            document["starting_state"] == "INITIAL_DEPLOYMENT"
            and (
                managed_checkout_commit is not None
                or prior_evidence_commit is not None
                or interrupted_redeployment
            )
        )
        or (
            document["starting_state"] == "MANAGED_REDEPLOYMENT"
            and (
                not isinstance(managed_checkout_commit, str)
                or re.fullmatch(
                    r"[0-9a-f]{40}",
                    managed_checkout_commit,
                )
                is None
                or not isinstance(prior_evidence_commit, str)
                or re.fullmatch(r"[0-9a-f]{40}", prior_evidence_commit)
                is None
                or interrupted_redeployment
                != (managed_checkout_commit != prior_evidence_commit)
            )
        )
        or document["compose_files"] != list(EXPECTED_COMPOSE_FILES)
        or not isinstance(document["cpu_limit"], str)
        or re.fullmatch(r"[0-9]+(?:[.][0-9]+)?", document["cpu_limit"]) is None
        or (
            memory_limit is not None
            and (
                not isinstance(memory_limit, str)
                or re.fullmatch(
                    r"[1-9][0-9]*(?:[bBkKmMgG]|[kKmMgG][bB])",
                    memory_limit,
                )
                is None
            )
        )
    ):
        raise ValueError("request values are invalid")
    return document


def _environment(request: dict[str, Any]) -> dict[str, str]:
    environment = os.environ.copy()
    environment.update(
        {
            "GIT_TERMINAL_PROMPT": "0",
            "LC_ALL": "C",
            "DOCKER_DEFAULT_PLATFORM": PLATFORM,
            "EVENTHORIZON_FIELD_AUTHORIZED": "yes",
            "FIELD_PROJECT_NAME": request["project_name"],
            "FIELD_TARPIT_CPU_LIMIT": request["cpu_limit"],
        }
    )
    if request["memory_limit"] is None:
        environment.pop("FIELD_TARPIT_MEMORY_LIMIT", None)
    else:
        environment["FIELD_TARPIT_MEMORY_LIMIT"] = request["memory_limit"]
    return environment


def _memory_limit_bytes(value: str | None) -> int | None:
    if value is None:
        return None
    match = re.fullmatch(
        r"([1-9][0-9]*)([bBkKmMgG]|[kKmMgG][bB])",
        value,
    )
    if match is None:
        raise DeploymentFailure(
            "BLOCKED",
            "Requested memory limit is invalid.",
        )
    unit = match.group(2).lower()
    if len(unit) == 2:
        unit = unit.removesuffix("b")
    multiplier = {
        "b": 1,
        "k": 1024,
        "m": 1024**2,
        "g": 1024**3,
    }[unit]
    return int(match.group(1), 10) * multiplier


def _run(
    arguments: Sequence[str],
    *,
    cwd: Path | None = None,
    environment: dict[str, str],
    timeout: int = 120,
) -> subprocess.CompletedProcess[str]:
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
    except (FileNotFoundError, subprocess.SubprocessError, OSError) as error:
        raise DeploymentFailure(
            "ERROR",
            "Required deployment tooling or infrastructure malfunctioned.",
        ) from error


def _require(
    completed: subprocess.CompletedProcess[str],
    *,
    outcome: str,
    blocker: str,
) -> str:
    if completed.returncode != 0:
        raise DeploymentFailure(outcome, blocker)
    if len(completed.stdout.encode("utf-8")) > 2 * 1024 * 1024:
        raise DeploymentFailure(
            "ERROR",
            "Deployment tooling returned unexpectedly large output.",
        )
    return completed.stdout


def _trusted_origin(origin: str) -> bool:
    return origin.removesuffix(".git") in {
        "https://github.com/honeynet/EventHorizon",
        "git@github.com:honeynet/EventHorizon",
        "ssh://git@github.com/honeynet/EventHorizon",
    }


def _prepare_checkout(
    request: dict[str, Any],
    environment: dict[str, str],
    mark_mutation: Callable[[], None],
) -> tuple[Path, str | None]:
    deploy_dir = Path(request["deploy_dir"])
    starting_state = request["starting_state"]
    prior_commit: str | None = None
    if deploy_dir.is_symlink():
        raise DeploymentFailure(
            "BLOCKED",
            "Deployment directory became a symlink after preflight.",
        )
    if starting_state == "INITIAL_DEPLOYMENT":
        if deploy_dir.exists() and (
            not deploy_dir.is_dir() or any(deploy_dir.iterdir())
        ):
            raise DeploymentFailure(
                "BLOCKED",
                "Initial deployment directory is no longer absent or empty.",
            )
        mark_mutation()
        deploy_dir.parent.mkdir(parents=True, exist_ok=True)
        staging_dir = Path(
            tempfile.mkdtemp(
                prefix=f".{deploy_dir.name}.clone-",
                dir=deploy_dir.parent,
            )
        )
        try:
            clone = _run(
                (
                    "git",
                    "clone",
                    "--no-checkout",
                    "--origin",
                    "origin",
                    TRUSTED_REPOSITORY_URL,
                    str(staging_dir),
                ),
                environment=environment,
                timeout=300,
            )
            _require(
                clone,
                outcome="ERROR",
                blocker="Trusted source checkout could not be created.",
            )
            if deploy_dir.exists():
                if (
                    deploy_dir.is_symlink()
                    or not deploy_dir.is_dir()
                    or any(deploy_dir.iterdir())
                ):
                    raise DeploymentFailure(
                        "BLOCKED",
                        "Initial deployment directory changed during checkout.",
                    )
                deploy_dir.rmdir()
            os.replace(staging_dir, deploy_dir)
        except OSError as error:
            raise DeploymentFailure(
                "ERROR",
                "Trusted source checkout could not be installed atomically.",
            ) from error
        finally:
            if staging_dir.exists():
                shutil.rmtree(staging_dir, ignore_errors=True)
    else:
        if not deploy_dir.is_dir() or not (deploy_dir / ".git").is_dir():
            raise DeploymentFailure(
                "BLOCKED",
                "Managed deployment checkout changed after preflight.",
            )
        origin = _require(
            _run(
                (
                    "git",
                    "-C",
                    str(deploy_dir),
                    "config",
                    "--get",
                    "remote.origin.url",
                ),
                environment=environment,
            ),
            outcome="ERROR",
            blocker="Managed checkout origin could not be inspected.",
        ).strip()
        if not _trusted_origin(origin):
            raise DeploymentFailure(
                "BLOCKED",
                "Managed checkout no longer uses the trusted repository.",
            )
        status = _require(
            _run(
                (
                    "git",
                    "-C",
                    str(deploy_dir),
                    "status",
                    "--porcelain",
                    "--untracked-files=normal",
                ),
                environment=environment,
            ),
            outcome="ERROR",
            blocker="Managed checkout cleanliness could not be inspected.",
        )
        if status:
            raise DeploymentFailure(
                "BLOCKED",
                "Managed checkout became dirty after preflight.",
            )
        prior_commit = _require(
            _run(
                ("git", "-C", str(deploy_dir), "rev-parse", "HEAD"),
                environment=environment,
            ),
            outcome="ERROR",
            blocker="Managed checkout identity could not be inspected.",
        ).strip()
        if prior_commit != request["managed_checkout_commit"]:
            raise DeploymentFailure(
                "BLOCKED",
                "Managed checkout changed after remote preflight.",
            )
        mark_mutation()

    fetch = _run(
        (
            "git",
            "-C",
            str(deploy_dir),
            "fetch",
            "--prune",
            "origin",
            (
                f"+refs/heads/{APPROVED_BRANCH}:"
                f"refs/remotes/origin/{APPROVED_BRANCH}"
            ),
        ),
        environment=environment,
        timeout=300,
    )
    _require(
        fetch,
        outcome="ERROR",
        blocker="Trusted approved branch could not be fetched.",
    )
    commit = request["deployment_commit"]
    commit_exists = _run(
        ("git", "-C", str(deploy_dir), "cat-file", "-e", f"{commit}^{{commit}}"),
        environment=environment,
    )
    if commit_exists.returncode != 0:
        raise DeploymentFailure(
            "BLOCKED",
            "Exact deployment commit is absent from the fetched repository.",
        )
    reachable = _run(
        (
            "git",
            "-C",
            str(deploy_dir),
            "merge-base",
            "--is-ancestor",
            commit,
            f"origin/{APPROVED_BRANCH}",
        ),
        environment=environment,
    )
    if reachable.returncode != 0:
        raise DeploymentFailure(
            "BLOCKED",
            "Exact deployment commit is not reachable from the approved branch.",
        )
    _require(
        _run(
            (
                "git",
                "-C",
                str(deploy_dir),
                "checkout",
                "--detach",
                "--force",
                commit,
            ),
            environment=environment,
        ),
        outcome="ERROR",
        blocker="Exact deployment commit could not be checked out.",
    )
    observed_head = _require(
        _run(
            ("git", "-C", str(deploy_dir), "rev-parse", "HEAD"),
            environment=environment,
        ),
        outcome="ERROR",
        blocker="Remote checkout identity could not be verified.",
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
            ),
            environment=environment,
        ),
        outcome="ERROR",
        blocker="Remote checkout cleanliness could not be verified.",
    )
    if observed_head != commit or status:
        raise DeploymentFailure(
            "FAIL",
            "Remote checkout did not settle at the exact clean deployment commit.",
        )
    return deploy_dir, prior_commit


def _load_commit_policy(
    deploy_dir: Path,
    request: dict[str, Any],
) -> dict[str, Any]:
    policy_path = deploy_dir / "deploy/deployment-policy.json"
    try:
        if policy_path.stat().st_size > 256 * 1024:
            raise ValueError
        policy = json.loads(policy_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise DeploymentFailure(
            "FAIL",
            "Deployment commit policy could not be validated.",
        ) from error
    if (
        not isinstance(policy, dict)
        or policy.get("trusted_repository") != TRUSTED_REPOSITORY
        or policy.get("approved_ref")
        != f"refs/remotes/upstream/{APPROVED_BRANCH}"
        or policy.get("supported_compose_files") != request["compose_files"]
        or not isinstance(policy.get("field_build"), dict)
        or policy["field_build"].get("platform") != PLATFORM
    ):
        raise DeploymentFailure(
            "BLOCKED",
            "Deployment commit policy does not match the authorized controller.",
        )
    return policy


def _compose_command(request: dict[str, Any]) -> list[str]:
    command = ["docker", "compose", "-p", request["project_name"]]
    for compose_file in request["compose_files"]:
        command.extend(("-f", compose_file))
    return command


def _normalize_rendered_config(
    rendered: dict[str, Any],
    raw_rendered: bytes,
    deploy_dir: Path,
    request: dict[str, Any],
    policy: dict[str, Any],
) -> dict[str, object]:
    services = rendered.get("services")
    volumes = rendered.get("volumes")
    if (
        not isinstance(services, dict)
        or set(services) != set(EXPECTED_SERVICES)
        or not isinstance(volumes, dict)
    ):
        raise DeploymentFailure(
            "FAIL",
            "Rendered Compose configuration has an unexpected field service set.",
        )
    field_build = policy["field_build"]
    dockerfiles = set(field_build.get("dockerfiles", []))
    pinned_images = set(field_build.get("compose_images", {}).values())
    normalized_services: list[dict[str, object]] = []
    for service_name in EXPECTED_SERVICES:
        service = services[service_name]
        if not isinstance(service, dict) or service.get("platform") != PLATFORM:
            raise DeploymentFailure(
                "FAIL",
                "Rendered Compose service platform violates field policy.",
            )
        build = service.get("build")
        image = service.get("image")
        if isinstance(build, dict):
            context = build.get("context")
            dockerfile = build.get("dockerfile")
            normalized_dockerfile = (
                dockerfile.removeprefix("./")
                if isinstance(dockerfile, str)
                else None
            )
            if (
                not isinstance(context, str)
                or Path(context).resolve() != deploy_dir.resolve()
                or normalized_dockerfile not in dockerfiles
            ):
                raise DeploymentFailure(
                    "FAIL",
                    "Rendered Compose build source violates exact-source policy.",
                )
            source_type = "BUILD"
            source = normalized_dockerfile
        elif isinstance(image, str) and image in pinned_images:
            source_type = "PINNED_IMAGE"
            source = image
        else:
            raise DeploymentFailure(
                "FAIL",
                "Rendered Compose image source is mutable or undeclared.",
            )
        ports = service.get("ports", [])
        if not isinstance(ports, list):
            raise DeploymentFailure(
                "FAIL",
                "Rendered Compose port configuration is malformed.",
            )
        normalized_ports: list[dict[str, object]] = []
        for port in ports:
            if (
                not isinstance(port, dict)
                or port.get("host_ip") not in {"0.0.0.0", "127.0.0.1"}
                or not isinstance(port.get("target"), int)
                or not str(port.get("published", "")).isdigit()
                or port.get("protocol") != "tcp"
            ):
                raise DeploymentFailure(
                    "FAIL",
                    "Rendered Compose port configuration violates field policy.",
                )
            normalized_ports.append(
                {
                    "host_ip": port["host_ip"],
                    "published": int(port["published"]),
                    "target": port["target"],
                    "protocol": "tcp",
                }
            )
        expected_port = {
            "prometheus-exporter": ("127.0.0.1", 9101, 9101),
            "telnet_pit": ("0.0.0.0", 23, 23),
            "mqtt_pit": ("0.0.0.0", 1883, 1883),
            "prometheus": ("127.0.0.1", 9090, 9090),
            "grafana": ("127.0.0.1", 3000, 3000),
            "cadvisor": ("127.0.0.1", 8081, 8080),
        }[service_name]
        if [
            (
                port["host_ip"],
                port["published"],
                port["target"],
            )
            for port in normalized_ports
        ] != [expected_port]:
            raise DeploymentFailure(
                "FAIL",
                "Rendered Compose bindings violate restricted field policy.",
            )
        logging = service.get("logging", {})
        logging_driver = (
            str(logging.get("driver", ""))
            if isinstance(logging, dict)
            else ""
        )
        expected_logging_driver = (
            "none"
            if service_name in {"mqtt_pit", "telnet_pit"}
            else "json-file"
        )
        is_tarpit = service_name in {"mqtt_pit", "telnet_pit"}
        cpu_limit = str(service["cpus"]) if "cpus" in service else None
        memory_limit = (
            int(service["mem_limit"])
            if str(service.get("mem_limit", "")).isdigit()
            and int(service["mem_limit"]) > 0
            else None
        )
        try:
            cpu_matches = (
                is_tarpit
                and cpu_limit is not None
                and Decimal(cpu_limit) == Decimal(request["cpu_limit"])
            )
        except InvalidOperation:
            cpu_matches = False
        if (
            service.get("restart") != "unless-stopped"
            or logging_driver != expected_logging_driver
            or bool(service.get("privileged", False))
            != (service_name == "cadvisor")
            or (is_tarpit and not cpu_matches)
            or (
                is_tarpit
                and memory_limit
                != _memory_limit_bytes(request["memory_limit"])
            )
            or (
                not is_tarpit
                and (cpu_limit is not None or memory_limit is not None)
            )
        ):
            raise DeploymentFailure(
                "FAIL",
                "Rendered Compose resource or runtime policy is invalid.",
            )
        normalized_volumes: list[dict[str, object]] = []
        for volume in service.get("volumes", []):
            if not isinstance(volume, dict) or not isinstance(
                volume.get("target"),
                str,
            ):
                raise DeploymentFailure(
                    "FAIL",
                    "Rendered Compose volume configuration is malformed.",
                )
            volume_type = volume.get("type")
            if volume_type not in {"bind", "volume"}:
                raise DeploymentFailure(
                    "FAIL",
                    "Rendered Compose volume type violates field policy.",
                )
            normalized_volumes.append(
                {
                    "type": volume_type,
                    "target": volume["target"],
                    "read_only": bool(volume.get("read_only", False)),
                }
            )
        normalized_services.append(
            {
                "name": service_name,
                "source_type": source_type,
                "source": source,
                "platform": PLATFORM,
                "ports": normalized_ports,
                "restart": str(service.get("restart", "")),
                "logging_driver": logging_driver,
                "cpu_limit": cpu_limit,
                "memory_limit_bytes": memory_limit,
                "privileged": bool(service.get("privileged", False)),
                "volumes": normalized_volumes,
            }
        )
    if set(volumes) != {"grafana-storage", "prometheus-data", "tarpit-sock"}:
        raise DeploymentFailure(
            "FAIL",
            "Rendered Compose volume set violates field persistence policy.",
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "deployment_commit": request["deployment_commit"],
        "project_name": request["project_name"],
        "platform": PLATFORM,
        "rendered_config_sha256": hashlib.sha256(raw_rendered).hexdigest(),
        "services": normalized_services,
        "volumes": sorted(volumes),
    }


def _service_image_ids(
    compose: Sequence[str],
    deploy_dir: Path,
    environment: dict[str, str],
    *,
    include_stopped: bool = False,
    missing_service_outcome: str = "FAIL",
    missing_service_blocker: str = (
        "Deployment did not create every required field service."
    ),
) -> dict[str, str]:
    image_ids: dict[str, str] = {}
    for service in EXPECTED_SERVICES:
        service_query = [
            *compose,
            "ps",
            *(("--all",) if include_stopped else ()),
            "-q",
            service,
        ]
        container_id = _require(
            _run(
                service_query,
                cwd=deploy_dir,
                environment=environment,
            ),
            outcome="ERROR",
            blocker="Deployed service identity could not be collected.",
        ).strip()
        if not container_id:
            raise DeploymentFailure(
                missing_service_outcome,
                missing_service_blocker,
            )
        image_id = _require(
            _run(
                ("docker", "inspect", "--format", "{{.Image}}", container_id),
                environment=environment,
            ),
            outcome="ERROR",
            blocker="Deployed image identity could not be collected.",
        ).strip()
        if re.fullmatch(r"sha256:[0-9a-f]{64}", image_id) is None:
            raise DeploymentFailure(
                "ERROR",
                "Docker returned a malformed deployed image identity.",
            )
        image_ids[service] = image_id
    return image_ids


def _volume_names(
    project_name: str,
    environment: dict[str, str],
) -> list[str]:
    output = _require(
        _run(
            (
                "docker",
                "volume",
                "ls",
                "--filter",
                f"label=com.docker.compose.project={project_name}",
                "--format",
                "{{.Name}}",
            ),
            environment=environment,
        ),
        outcome="ERROR",
        blocker="Deployment volume identities could not be collected.",
    )
    names = sorted(line for line in output.splitlines() if line)
    if not all(
        re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}", name)
        for name in names
    ):
        raise DeploymentFailure(
            "ERROR",
            "Docker returned a malformed volume identity.",
        )
    return names


def _atomic_json(path: Path, document: dict[str, object]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.parent.chmod(0o700)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        dir=path.parent,
    )
    temporary_path = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as target:
            target.write(
                (
                    json.dumps(
                        document,
                        indent=2,
                        sort_keys=True,
                    )
                    + "\n"
                ).encode("utf-8")
            )
            target.flush()
            os.fsync(target.fileno())
        os.replace(temporary_path, path)
    except BaseException:
        temporary_path.unlink(missing_ok=True)
        raise


def _prepare_remote_run_directory(deploy_dir: Path, run_id: str) -> Path:
    validation_output = deploy_dir / "validation-output"
    deployments = validation_output / "deployments"
    for path in (validation_output, deployments):
        if path.is_symlink():
            raise DeploymentFailure(
                "BLOCKED",
                "Remote evidence path became a symlink.",
            )
        if path.exists():
            details = path.stat()
            if (
                not path.is_dir()
                or details.st_uid != os.getuid()
                or stat.S_IMODE(details.st_mode) & 0o022
            ):
                raise DeploymentFailure(
                    "BLOCKED",
                    "Remote evidence path has unsafe ownership or permissions.",
                )
        else:
            path.mkdir(mode=0o700)
    run_directory = deployments / run_id
    if run_directory.exists() or run_directory.is_symlink():
        raise DeploymentFailure(
            "BLOCKED",
            "Remote evidence run identifier already exists.",
        )
    run_directory.mkdir(mode=0o700)
    return run_directory


def _write_remote_artifacts(
    run_directory: Path,
    compose_config: dict[str, object],
    deployment_manifest: dict[str, object],
) -> None:
    try:
        _atomic_json(run_directory / "compose-config.json", compose_config)
        _atomic_json(
            run_directory / "deployment-manifest.json",
            deployment_manifest,
        )
    except OSError as error:
        raise DeploymentFailure(
            "ERROR",
            "Remote deployment evidence could not be written safely.",
        ) from error


def _response(
    request: dict[str, Any],
    *,
    result: str,
    blocker: str | None,
    mutation: bool,
    services_running: bool,
    compose_config: dict[str, object],
    deployment_manifest: dict[str, object],
) -> dict[str, object]:
    return {
        "schema_version": SCHEMA_VERSION,
        "run_id": request["run_id"],
        "target_alias": request["target_alias"],
        "deployment_commit": request["deployment_commit"],
        "result": result,
        "blocker": blocker,
        "remote_mutation_occurred": mutation,
        "field_services_running": services_running,
        "compose_config": compose_config,
        "deployment_manifest": deployment_manifest,
    }


def _deploy(request: dict[str, Any]) -> dict[str, object]:
    environment = _environment(request)
    mutation_started = False
    up_attempted = False
    services_running = False
    compose_config: dict[str, object] = {}
    deployment_manifest: dict[str, object] = {}
    compose: list[str] = []
    run_directory: Path | None = None
    deploy_dir = Path(request["deploy_dir"])
    prior_commit: str | None = None

    def mark_mutation() -> None:
        nonlocal mutation_started
        mutation_started = True

    try:
        deploy_dir, prior_commit = _prepare_checkout(
            request,
            environment,
            mark_mutation,
        )
        policy = _load_commit_policy(deploy_dir, request)
        compose = _compose_command(request)
        rendered_output = _require(
            _run(
                (*compose, "config", "--format", "json"),
                cwd=deploy_dir,
                environment=environment,
            ),
            outcome="FAIL",
            blocker="Supported field Compose configuration did not render.",
        )
        try:
            rendered = json.loads(rendered_output)
        except json.JSONDecodeError as error:
            raise DeploymentFailure(
                "FAIL",
                "Rendered Compose configuration was not valid JSON.",
            ) from error
        if not isinstance(rendered, dict):
            raise DeploymentFailure(
                "FAIL",
                "Rendered Compose configuration was not an object.",
            )
        compose_config = _normalize_rendered_config(
            rendered,
            rendered_output.encode("utf-8"),
            deploy_dir,
            request,
            policy,
        )
        docker_version = _require(
            _run(
                ("docker", "version", "--format", "{{.Server.Version}}"),
                environment=environment,
            ),
            outcome="ERROR",
            blocker="Docker version evidence could not be collected.",
        ).strip()
        compose_version = _require(
            _run(
                ("docker", "compose", "version", "--short"),
                environment=environment,
            ),
            outcome="ERROR",
            blocker="Docker Compose version evidence could not be collected.",
        ).strip()
        field_build = policy["field_build"]
        pinned_inputs = sorted(
            [
                *field_build.get("base_images", []),
                *field_build.get("compose_images", {}).values(),
            ]
        )
        prior_image_ids: dict[str, str] = {}
        prior_volumes: list[str] = []
        if request["starting_state"] == "MANAGED_REDEPLOYMENT":
            prior_image_ids = _service_image_ids(
                compose,
                deploy_dir,
                environment,
                include_stopped=True,
                missing_service_outcome="BLOCKED",
                missing_service_blocker=(
                    "Managed deployment no longer contains every "
                    "evidenced field service."
                ),
            )
            prior_volumes = _volume_names(
                request["project_name"],
                environment,
            )
        deployment_manifest = {
            "schema_version": SCHEMA_VERSION,
            "run_id": request["run_id"],
            "target_alias": request["target_alias"],
            "deployment_commit": request["deployment_commit"],
            "repository_commit": request["deployment_commit"],
            "compose_project_name": request["project_name"],
            "trusted_repository": TRUSTED_REPOSITORY,
            "approved_branch": APPROVED_BRANCH,
            "starting_state": request["starting_state"],
            "deployed_utc": _utc_now(),
            "platform": PLATFORM,
            "head_verified": True,
            "worktree_clean": True,
            "docker_version": docker_version,
            "compose_version": compose_version,
            "rendered_compose_sha256": compose_config[
                "rendered_config_sha256"
            ],
            "pinned_inputs": pinned_inputs,
            "service_image_ids": {},
            "volume_names": prior_volumes,
            "prior_deployment": {
                "commit": prior_commit,
                "service_image_ids": prior_image_ids,
                "volume_names": prior_volumes,
            },
            "cleanup": {
                "attempted": False,
                "succeeded": None,
            },
            "result": "INCONCLUSIVE",
        }
        run_directory = _prepare_remote_run_directory(
            deploy_dir,
            request["run_id"],
        )
        _write_remote_artifacts(
            run_directory,
            compose_config,
            deployment_manifest,
        )
        up_attempted = True
        _require(
            _run(
                (*compose, "up", "-d", "--build", "--remove-orphans"),
                cwd=deploy_dir,
                environment=environment,
                timeout=1200,
            ),
            outcome="ERROR",
            blocker="Docker Compose could not build and start the field project.",
        )
        services_running = True
        image_ids = _service_image_ids(
            compose,
            deploy_dir,
            environment,
        )
        volumes = _volume_names(request["project_name"], environment)
        deployment_manifest["service_image_ids"] = image_ids
        deployment_manifest["volume_names"] = volumes
        deployment_manifest["result"] = "PASS"
        _write_remote_artifacts(
            run_directory,
            compose_config,
            deployment_manifest,
        )
        return _response(
            request,
            result="PASS",
            blocker=None,
            mutation=True,
            services_running=True,
            compose_config=compose_config,
            deployment_manifest=deployment_manifest,
        )
    except DeploymentFailure as failure:
        failure_outcome = failure.outcome
        failure_blocker = failure.blocker
        cleanup_attempted = False
        cleanup_succeeded: bool | None = None
        if up_attempted and compose and deploy_dir.is_dir():
            cleanup_attempted = True
            stopped = _run(
                (*compose, "stop"),
                cwd=deploy_dir,
                environment=environment,
                timeout=180,
            )
            cleanup_succeeded = stopped.returncode == 0
            services_running = not cleanup_succeeded
            if not cleanup_succeeded:
                failure_outcome = "ERROR"
                failure_blocker = (
                    "Deployment failed and field-service cleanup could not be "
                    "proven; inspect and stop the authorized project."
                )
        if deployment_manifest:
            deployment_manifest["result"] = failure_outcome
            deployment_manifest["cleanup"] = {
                "attempted": cleanup_attempted,
                "succeeded": cleanup_succeeded,
            }
            if run_directory is not None:
                try:
                    _write_remote_artifacts(
                        run_directory,
                        compose_config,
                        deployment_manifest,
                    )
                except DeploymentFailure:
                    failure_outcome = "ERROR"
                    failure_blocker = (
                        "Deployment failed and partial evidence could not be "
                        "written safely."
                    )
        return _response(
            request,
            result=failure_outcome,
            blocker=failure_blocker,
            mutation=mutation_started,
            services_running=services_running,
            compose_config=compose_config,
            deployment_manifest=deployment_manifest,
        )


def main(arguments: Sequence[str] | None = None) -> int:
    raw_arguments = list(sys.argv[1:] if arguments is None else arguments)
    if raw_arguments in (["-h"], ["--help"]):
        print("usage: vps_field_remote_deploy.py <encoded-request>")
        print(
            "Validate an exact trusted commit and deploy its supported field "
            "Compose profile."
        )
        return 0
    if len(raw_arguments) != 1:
        print("remote deployment request is required", file=sys.stderr)
        return 2
    try:
        request = _decode_request(raw_arguments[0])
    except (ValueError, UnicodeError, json.JSONDecodeError):
        print("remote deployment request is invalid", file=sys.stderr)
        return 2
    try:
        response = _deploy(request)
    except BaseException:
        response = _response(
            request,
            result="ERROR",
            blocker="Remote deployment program malfunctioned.",
            mutation=True,
            services_running=True,
            compose_config={},
            deployment_manifest={},
        )
    print(json.dumps(response, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
