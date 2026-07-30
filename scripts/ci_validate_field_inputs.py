#!/usr/bin/env python3
"""Validate the declared field build graph and rendered Compose safety policy."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
PINNED_IMAGE = re.compile(
    r"^[A-Za-z0-9./_-]+:[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}$"
)
PINNED_FROM = re.compile(
    r"^FROM (?P<image>[A-Za-z0-9./_-]+:[A-Za-z0-9._-]+"
    r"@sha256:[0-9a-f]{64})(?: AS [A-Za-z0-9._-]+)?$"
)


def load_json(path: Path) -> dict[str, object]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{path.name} is not readable JSON") from error
    if not isinstance(document, dict):
        raise ValueError(f"{path.name} must contain a JSON object")
    return document


def validate_dockerfiles(field_build: dict[str, object]) -> list[str]:
    errors: list[str] = []
    declared_images = field_build.get("base_images")
    dockerfiles = field_build.get("dockerfiles")
    if not isinstance(declared_images, list) or not all(
        isinstance(image, str) for image in declared_images
    ):
        return ["field_build.base_images is malformed"]
    if not isinstance(dockerfiles, list) or not all(
        isinstance(path, str) for path in dockerfiles
    ):
        return ["field_build.dockerfiles is malformed"]

    observed_images: set[str] = set()
    forbidden = ("apt ", "apt-get ", "apk ", "curl ", "wget ", "git clone")
    for relative_path in dockerfiles:
        path = REPO_ROOT / relative_path
        try:
            content = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            errors.append(f"declared Dockerfile is unreadable: {relative_path}")
            continue
        from_lines = [
            line
            for line in content.splitlines()
            if line.startswith("FROM ")
        ]
        if not from_lines:
            errors.append(f"{relative_path} has no FROM instruction")
        for line in from_lines:
            match = PINNED_FROM.fullmatch(line)
            if match is None:
                errors.append(f"{relative_path} has an unpinned FROM instruction")
            else:
                observed_images.add(match.group("image"))
        lowered = content.lower()
        for command in forbidden:
            if command in lowered:
                errors.append(
                    f"{relative_path} uses undeclared network/package input {command!r}"
                )

    if observed_images != set(declared_images):
        errors.append("Dockerfile base images differ from deployment policy")

    go_path = REPO_ROOT / "docker/prometheus/Dockerfile"
    try:
        go_content = go_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        errors.append("Go field Dockerfile is unreadable")
    else:
        required_fragments = (
            "golang:1.23.9-bookworm@sha256:",
            "GOTOOLCHAIN=local",
            "GOFLAGS=-mod=readonly",
            "COPY prometheus/go.mod prometheus/go.sum ./",
            "sha256sum -c /tmp/go-modules.sha256",
            "go build -mod=readonly",
        )
        for fragment in required_fragments:
            if fragment not in go_content:
                errors.append(f"Go field Dockerfile is missing {fragment!r}")
    return errors


def normalized_port(port: dict[str, object]) -> tuple[str, str, int, str]:
    target = port.get("target")
    if isinstance(target, int):
        target_port = target
    elif isinstance(target, str) and target.isdigit():
        target_port = int(target, 10)
    else:
        target_port = -1
    return (
        str(port.get("host_ip", "")),
        str(port.get("published", "")),
        target_port,
        str(port.get("protocol", "")),
    )


def validate_compose(
    compose: dict[str, object],
    field_build: dict[str, object],
) -> list[str]:
    errors: list[str] = []
    services = compose.get("services")
    if not isinstance(services, dict):
        return ["rendered Compose configuration has no services object"]

    expected_services = {
        "prometheus-exporter",
        "telnet_pit",
        "mqtt_pit",
        "prometheus",
        "grafana",
        "cadvisor",
    }
    missing = expected_services - set(services)
    if missing:
        errors.append("rendered field profile is missing required services")
    for service_name in expected_services:
        service = services.get(service_name)
        if (
            isinstance(service, dict)
            and service.get("platform") != field_build.get("platform")
        ):
            errors.append(
                f"rendered field platform is not policy-pinned: {service_name}"
            )

    declared_compose_images = field_build.get("compose_images")
    if not isinstance(declared_compose_images, dict):
        errors.append("field_build.compose_images is malformed")
    else:
        for service_name, expected_image in declared_compose_images.items():
            service = services.get(service_name)
            if not isinstance(service, dict) or not isinstance(expected_image, str):
                errors.append(f"rendered field image is missing for {service_name}")
                continue
            observed_image = service.get("image")
            if observed_image != expected_image or not PINNED_IMAGE.fullmatch(
                str(observed_image)
            ):
                errors.append(f"rendered field image is not policy-pinned: {service_name}")

    public_ports = {
        "telnet_pit": ("0.0.0.0", "23", 23, "tcp"),
        "mqtt_pit": ("0.0.0.0", "1883", 1883, "tcp"),
    }
    private_ports = {
        "prometheus-exporter": ("127.0.0.1", "9101", 9101, "tcp"),
        "prometheus": ("127.0.0.1", "9090", 9090, "tcp"),
        "grafana": ("127.0.0.1", "3000", 3000, "tcp"),
        "cadvisor": ("127.0.0.1", "8081", 8080, "tcp"),
    }
    for service_name, expected in (public_ports | private_ports).items():
        service = services.get(service_name)
        if not isinstance(service, dict):
            continue
        ports = service.get("ports")
        if (
            not isinstance(ports, list)
            or len(ports) != 1
            or not isinstance(ports[0], dict)
            or normalized_port(ports[0]) != expected
        ):
            errors.append(f"rendered field port policy is invalid: {service_name}")

    exporter = services.get("prometheus-exporter")
    if isinstance(exporter, dict):
        environment = exporter.get("environment")
        if (
            not isinstance(environment, dict)
            or str(environment.get("EVENTHORIZON_FIELD_SAFE_MODE")).lower() != "true"
        ):
            errors.append("exporter field-safe mode is not enabled")

    for service_name in ("telnet_pit", "mqtt_pit"):
        service = services.get(service_name)
        if not isinstance(service, dict):
            continue
        logging = service.get("logging")
        environment = service.get("environment")
        if not isinstance(logging, dict) or logging.get("driver") != "none":
            errors.append(f"raw container logging is not disabled: {service_name}")
        if (
            not isinstance(environment, dict)
            or environment.get("EVENTHORIZON_SESSION_LOG") != "/dev/null"
        ):
            errors.append(f"raw session logging is not disabled: {service_name}")

    expected_builds = {
        "prometheus-exporter": "docker/prometheus/Dockerfile",
        "telnet_pit": "docker/tarpits/Dockerfile",
        "mqtt_pit": "docker/tarpits/Dockerfile",
    }
    for service_name, expected_dockerfile in expected_builds.items():
        service = services.get(service_name)
        build = service.get("build") if isinstance(service, dict) else None
        dockerfile = build.get("dockerfile") if isinstance(build, dict) else None
        if str(dockerfile).removeprefix("./") != expected_dockerfile:
            errors.append(f"rendered build graph is invalid: {service_name}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate immutable field inputs and rendered Compose policy."
    )
    parser.add_argument("--compose-json", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()

    policy = load_json(REPO_ROOT / "deploy/deployment-policy.json")
    field_build = policy.get("field_build")
    if not isinstance(field_build, dict):
        errors = ["deployment policy has no field_build object"]
    elif field_build.get("platform") != "linux/amd64":
        errors = ["supported field platform must be linux/amd64"]
    else:
        errors = validate_dockerfiles(field_build)
        errors.extend(
            validate_compose(load_json(arguments.compose_json), field_build)
        )

    result = {
        "schema_version": 1,
        "platform": "linux/amd64",
        "status": "PASS" if not errors else "FAIL",
        "checks": {
            "pinned_field_inputs": not any("image" in error for error in errors),
            "declared_build_graph": not any("build" in error for error in errors),
            "field_overlay_policy": not any(
                word in error
                for error in errors
                for word in ("port", "logging", "field-safe", "platform")
            ),
        },
        "errors": errors,
    }
    arguments.output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    arguments.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if not errors else 1


if __name__ == "__main__":
    sys.exit(main())
