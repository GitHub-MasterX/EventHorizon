#!/usr/bin/env python3
"""Finalize one bounded EventHorizon evidence bundle on an authorized VPS."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence


SCHEMA_VERSION = 1
RUN_ID_PATTERN = re.compile(
    r"deploy-[0-9]{8}T[0-9]{6}Z-[a-z0-9]{6,32}"
)
FULL_SHA_PATTERN = re.compile(r"[0-9a-f]{40}")
TARGET_ALIAS_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
EXISTING_FILENAMES = (
    "compose-config.json",
    "deployment-manifest.json",
)
INCOMING_FILENAMES = (
    "remote-preflight.json",
    "health-and-ports.json",
    "protocol-smoke.json",
)
EVIDENCE_FILENAMES = (
    "remote-preflight.json",
    "compose-config.json",
    "deployment-manifest.json",
    "health-and-ports.json",
    "protocol-smoke.json",
)
MAX_ARTIFACT_BYTES = 1024 * 1024


class EvidenceFailure(RuntimeError):
    """A bounded finalization failure safe to report to the controller."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _decode_request(encoded: str) -> tuple[dict[str, Any], dict[str, bytes]]:
    if len(encoded) > 4 * 1024 * 1024:
        raise EvidenceFailure("Final evidence request exceeded its bound.")
    try:
        raw = base64.b64decode(
            encoded.encode("ascii"),
            altchars=b"-_",
            validate=True,
        )
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeError, binascii.Error, json.JSONDecodeError) as error:
        raise EvidenceFailure("Final evidence request was malformed.") from error
    if (
        not isinstance(document, dict)
        or set(document)
        != {
            "schema_version",
            "run_id",
            "target_alias",
            "deployment_commit",
            "deploy_dir",
            "artifacts",
        }
        or document["schema_version"] != SCHEMA_VERSION
        or not isinstance(document["run_id"], str)
        or RUN_ID_PATTERN.fullmatch(document["run_id"]) is None
        or not isinstance(document["target_alias"], str)
        or TARGET_ALIAS_PATTERN.fullmatch(document["target_alias"]) is None
        or not isinstance(document["deployment_commit"], str)
        or FULL_SHA_PATTERN.fullmatch(document["deployment_commit"]) is None
        or not isinstance(document["deploy_dir"], str)
        or not isinstance(document["artifacts"], list)
        or len(document["artifacts"]) != len(INCOMING_FILENAMES)
    ):
        raise EvidenceFailure("Final evidence request fields were invalid.")
    deploy_dir = Path(document["deploy_dir"])
    if (
        not deploy_dir.is_absolute()
        or ".." in deploy_dir.parts
        or len(deploy_dir.parts) < 3
        or deploy_dir in {Path("/"), Path("/home"), Path("/root"), Path("/srv")}
    ):
        raise EvidenceFailure("Deployment evidence path was unsafe.")
    artifacts: dict[str, bytes] = {}
    for entry in document["artifacts"]:
        if (
            not isinstance(entry, dict)
            or set(entry) != {"filename", "content_base64"}
            or entry["filename"] not in INCOMING_FILENAMES
            or entry["filename"] in artifacts
            or not isinstance(entry["content_base64"], str)
        ):
            raise EvidenceFailure("Final evidence artifact list was invalid.")
        try:
            content = base64.b64decode(
                entry["content_base64"],
                validate=True,
            )
        except (binascii.Error, ValueError) as error:
            raise EvidenceFailure("Final evidence artifact was malformed.") from error
        if len(content) > MAX_ARTIFACT_BYTES:
            raise EvidenceFailure("Final evidence artifact exceeded its bound.")
        artifacts[str(entry["filename"])] = content
    if set(artifacts) != set(INCOMING_FILENAMES):
        raise EvidenceFailure("Final evidence artifact allowlist was incomplete.")
    return document, artifacts


def _json_document(content: bytes, filename: str) -> dict[str, Any]:
    try:
        document = json.loads(content.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise EvidenceFailure(
            "Final evidence artifact was not valid JSON."
        ) from error
    if not isinstance(document, dict):
        raise EvidenceFailure("Final evidence artifact was not a JSON object.")
    expected_version = 2 if filename == "remote-preflight.json" else 1
    if document.get("schema_version") != expected_version:
        raise EvidenceFailure("Final evidence artifact schema was unsupported.")
    return document


def _identity_is_valid(
    document: dict[str, Any],
    filename: str,
    request: dict[str, Any],
) -> bool:
    if document.get("deployment_commit") != request["deployment_commit"]:
        return False
    if filename != "compose-config.json" and document.get("result") != "PASS":
        return False
    if filename != "compose-config.json" and (
        document.get("target_alias") != request["target_alias"]
    ):
        return False
    if filename in {
        "deployment-manifest.json",
        "health-and-ports.json",
        "protocol-smoke.json",
    } and document.get("run_id") != request["run_id"]:
        return False
    return True


def _safe_directory(path: Path) -> None:
    if path.is_symlink() or not path.is_dir():
        raise EvidenceFailure("Remote evidence directory was unsafe.")
    details = path.stat()
    if details.st_uid != os.getuid() or stat.S_IMODE(details.st_mode) & 0o022:
        raise EvidenceFailure("Remote evidence directory permissions were unsafe.")


def _read_safe_artifact(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise EvidenceFailure("Expected remote deployment evidence was missing.")
    details = path.stat()
    if (
        details.st_uid != os.getuid()
        or stat.S_IMODE(details.st_mode) & 0o022
        or details.st_size > MAX_ARTIFACT_BYTES
    ):
        raise EvidenceFailure("Expected remote deployment evidence was unsafe.")
    try:
        return path.read_bytes()
    except OSError as error:
        raise EvidenceFailure(
            "Expected remote deployment evidence could not be read."
        ) from error


def _atomic_write(path: Path, content: bytes) -> None:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        dir=path.parent,
    )
    temporary_path = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as target:
            target.write(content)
            target.flush()
            os.fsync(target.fileno())
        os.replace(temporary_path, path)
    except BaseException:
        temporary_path.unlink(missing_ok=True)
        raise


def _exact_checkout_is_valid(deploy_dir: Path, commit: str) -> bool:
    environment = os.environ.copy()
    environment.update({"GIT_TERMINAL_PROMPT": "0", "LC_ALL": "C"})
    try:
        head = subprocess.run(
            ["git", "-C", str(deploy_dir), "rev-parse", "HEAD"],
            text=True,
            capture_output=True,
            check=False,
            env=environment,
            timeout=30,
        )
        status = subprocess.run(
            [
                "git",
                "-C",
                str(deploy_dir),
                "status",
                "--porcelain",
                "--untracked-files=normal",
            ],
            text=True,
            capture_output=True,
            check=False,
            env=environment,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise EvidenceFailure(
            "Remote checkout identity could not be verified."
        ) from error
    return (
        head.returncode == 0
        and head.stdout.strip() == commit
        and status.returncode == 0
        and status.stdout == ""
    )


def _finalize(
    request: dict[str, Any],
    incoming: dict[str, bytes],
) -> dict[str, object]:
    deploy_dir = Path(request["deploy_dir"])
    if deploy_dir.is_symlink() or not deploy_dir.is_dir():
        raise EvidenceFailure("Exact deployment checkout was unavailable.")
    if not _exact_checkout_is_valid(deploy_dir, request["deployment_commit"]):
        raise EvidenceFailure("Exact deployment checkout identity changed.")
    validation_output = deploy_dir / "validation-output"
    deployments = validation_output / "deployments"
    run_directory = deployments / request["run_id"]
    for path in (validation_output, deployments, run_directory):
        _safe_directory(path)

    contents: dict[str, bytes] = {}
    for filename in EXISTING_FILENAMES:
        content = _read_safe_artifact(run_directory / filename)
        document = _json_document(content, filename)
        if not _identity_is_valid(document, filename, request):
            raise EvidenceFailure("Remote deployment evidence identity mismatched.")
        contents[filename] = content

    final_paths = [
        *(run_directory / filename for filename in INCOMING_FILENAMES),
        run_directory / "evidence-index.json",
    ]
    if any(path.exists() or path.is_symlink() for path in final_paths):
        raise EvidenceFailure("Remote final evidence already existed.")

    for filename in INCOMING_FILENAMES:
        path = run_directory / filename
        document = _json_document(incoming[filename], filename)
        if not _identity_is_valid(document, filename, request):
            raise EvidenceFailure("Final evidence artifact identity mismatched.")
        try:
            _atomic_write(path, incoming[filename])
        except OSError as error:
            raise EvidenceFailure(
                "Remote final evidence could not be written atomically."
            ) from error
        contents[filename] = incoming[filename]

    ordered_contents = {
        filename: contents[filename] for filename in EVIDENCE_FILENAMES
    }
    index = {
        "schema_version": SCHEMA_VERSION,
        "run_id": request["run_id"],
        "generated_utc": _utc_now(),
        "artifacts": [
            {
                "filename": filename,
                "size_bytes": len(content),
                "sha256": hashlib.sha256(content).hexdigest(),
                "collection_status": "COLLECTED",
                "reason": None,
            }
            for filename, content in ordered_contents.items()
        ],
    }
    try:
        _atomic_write(
            run_directory / "evidence-index.json",
            (json.dumps(index, indent=2, sort_keys=True) + "\n").encode(
                "utf-8"
            ),
        )
    except OSError as error:
        raise EvidenceFailure(
            "Remote evidence index could not be written atomically."
        ) from error
    return {
        "schema_version": SCHEMA_VERSION,
        "run_id": request["run_id"],
        "target_alias": request["target_alias"],
        "deployment_commit": request["deployment_commit"],
        "result": "PASS",
        "blocker": None,
        "index": index,
        "artifacts": [
            {
                "filename": filename,
                "content_base64": base64.b64encode(content).decode("ascii"),
            }
            for filename, content in ordered_contents.items()
        ],
    }


def main(arguments: Sequence[str] | None = None) -> int:
    raw_arguments = list(sys.argv[1:] if arguments is None else arguments)
    if raw_arguments in (["-h"], ["--help"]):
        print("usage: vps_field_remote_evidence.py <encoded-request>")
        print("Finalize and return one allowlisted deployment evidence bundle.")
        return 0
    if len(raw_arguments) != 1:
        print("remote evidence request is required", file=sys.stderr)
        return 2
    request: dict[str, Any] | None = None
    try:
        request, incoming = _decode_request(raw_arguments[0])
        response = _finalize(request, incoming)
    except EvidenceFailure as failure:
        if request is None:
            print(str(failure), file=sys.stderr)
            return 2
        response = {
            "schema_version": SCHEMA_VERSION,
            "run_id": request["run_id"],
            "target_alias": request["target_alias"],
            "deployment_commit": request["deployment_commit"],
            "result": "ERROR",
            "blocker": str(failure),
            "index": None,
            "artifacts": [],
        }
    print(json.dumps(response, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
