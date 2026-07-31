#!/usr/bin/env python3
"""EventHorizon's supported exact-commit deployment controller."""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import hashlib
import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path, PurePosixPath
from typing import NoReturn, Protocol, Sequence, TextIO


RESULT_SCHEMA_VERSION = 1
EVIDENCE_INDEX_SCHEMA_VERSION = 1
CI_PROOF_SCHEMA_VERSION = 1
REMOTE_PREFLIGHT_SCHEMA_VERSION = 2
COMPOSE_CONFIG_SCHEMA_VERSION = 1
DEPLOYMENT_MANIFEST_SCHEMA_VERSION = 1
HEALTH_AND_PORTS_SCHEMA_VERSION = 1
CONTROLLER_CONTRACT_VERSION = 1
REPO_ROOT = Path(__file__).resolve().parents[1]
FULL_SHA_PATTERN = re.compile(r"^[0-9a-fA-F]{40}$")
EXPECTED_EVIDENCE = (
    "result.json",
    "summary.md",
    "controller-manifest.json",
    "ci-proof.json",
    "authorization.json",
    "remote-preflight.json",
    "compose-config.json",
    "deployment-manifest.json",
    "health-and-ports.json",
    "protocol-smoke.json",
    "diagnostics.json",
)
EXIT_CODES = {
    "PASS": 0,
    "BLOCKED": 2,
    "FAIL": 3,
    "INCONCLUSIVE": 4,
    "ERROR": 5,
    "CANCELLED": 6,
}


class Clock(Protocol):
    def now(self) -> datetime:
        """Return the current timezone-aware UTC time."""


class RandomSource(Protocol):
    def run_suffix(self) -> str:
        """Return a lowercase collision-resistant run suffix."""


@dataclass(frozen=True)
class CandidateVerification:
    passed: bool
    protected_hashes: dict[str, str]
    warnings: tuple[str, ...]
    blocker: str | None


@dataclass(frozen=True)
class CiVerification:
    passed: bool
    proof: dict[str, object]
    blocker: str | None
    outcome: str = "BLOCKED"


@dataclass(frozen=True)
class RemotePreflightVerification:
    passed: bool
    evidence: dict[str, object]
    blocker: str | None
    outcome: str = "BLOCKED"


@dataclass(frozen=True)
class RemoteDeploymentVerification:
    passed: bool
    outcome: str
    blocker: str | None
    remote_mutation_occurred: bool
    field_services_running: bool
    compose_config: dict[str, object]
    deployment_manifest: dict[str, object]


@dataclass(frozen=True)
class RuntimeVerification:
    passed: bool
    outcome: str
    blocker: str | None
    field_services_running: bool
    evidence: dict[str, object]
    observed_public_ports: tuple[int, ...]
    observed_private_ports: tuple[int, ...]


@dataclass(frozen=True)
class RemoteProbeExecution:
    returncode: int
    stdout: bytes
    stderr: bytes


@dataclass(frozen=True)
class RemoteDeploymentExecution:
    returncode: int
    stdout: bytes
    stderr: bytes


@dataclass(frozen=True)
class RemoteRuntimeExecution:
    returncode: int
    stdout: bytes
    stderr: bytes


@dataclass(frozen=True)
class AuthorizationDecision:
    authorized: bool


class RepositoryCapabilities(Protocol):
    def verify_candidate(
        self,
        commit: str,
        policy: dict[str, object],
    ) -> CandidateVerification:
        """Prove the candidate and protected controller compatibility."""

    def target_file_is_ignored(self, path: Path) -> bool:
        """Return whether Git excludes the operator target file."""


class TrustedCiCapabilities(Protocol):
    def verify(
        self,
        commit: str,
        policy: dict[str, object],
    ) -> CiVerification:
        """Prove trusted CI for the exact deployment commit."""


class GitHubActionsApi(Protocol):
    def list_workflow_runs(
        self,
        repository: str,
        workflow_path: str,
        event: str,
        head_sha: str,
        head_branch: str,
    ) -> list[dict[str, object]]:
        """Return workflow runs filtered to an exact candidate."""

    def list_run_attempt_jobs(
        self,
        repository: str,
        run_id: int,
        run_attempt: int,
    ) -> list[dict[str, object]]:
        """Return jobs for one exact workflow run attempt."""


class RemoteCapabilities(Protocol):
    def preflight(
        self,
        configuration: TargetConfiguration,
        commit: str,
        policy: dict[str, object],
    ) -> RemotePreflightVerification:
        """Prove the non-mutating authorized-VPS preflight contract."""


class DeploymentCapabilities(Protocol):
    def deploy(
        self,
        configuration: TargetConfiguration,
        commit: str,
        policy: dict[str, object],
        preflight: dict[str, object],
        run_id: str,
    ) -> RemoteDeploymentVerification:
        """Deploy one exact source commit and return bounded evidence."""


class RuntimeCapabilities(Protocol):
    def verify(
        self,
        configuration: TargetConfiguration,
        commit: str,
        policy: dict[str, object],
        deployment_manifest: dict[str, object],
        run_id: str,
    ) -> RuntimeVerification:
        """Verify runtime health, bindings, and workstation reachability."""


class RemoteProbeCapabilities(Protocol):
    def collect(
        self,
        configuration: TargetConfiguration,
        commit: str,
        policy: dict[str, object],
    ) -> RemoteProbeExecution:
        """Collect one bounded remote preflight document over SSH."""


class RemoteDeploymentTransportCapabilities(Protocol):
    def execute(
        self,
        configuration: TargetConfiguration,
        commit: str,
        policy: dict[str, object],
        preflight: dict[str, object],
        run_id: str,
    ) -> RemoteDeploymentExecution:
        """Execute one authorized remote deployment and return bounded output."""


class RuntimeRemoteTransportCapabilities(Protocol):
    def inspect(
        self,
        configuration: TargetConfiguration,
        commit: str,
        expected_image_ids: dict[str, str],
        run_id: str,
    ) -> RemoteRuntimeExecution:
        """Collect bounded remote runtime health and binding evidence."""

    def stop(
        self,
        configuration: TargetConfiguration,
        commit: str,
        run_id: str,
    ) -> bool:
        """Stop the exact managed field service set after a later failure."""


class WorkstationPortCapabilities(Protocol):
    def observe(
        self,
        host: str,
        ports: tuple[int, ...],
    ) -> dict[int, bool]:
        """Observe bounded TCP reachability from the operator workstation."""


class AuthorizationCapabilities(Protocol):
    def authorize(self, phrase: str) -> AuthorizationDecision:
        """Request exact-commit interactive operator authorization."""


@dataclass(frozen=True)
class InteractiveTtyAuthorization:
    authorization_input: TextIO
    prompt_output: TextIO

    def authorize(self, phrase: str) -> AuthorizationDecision:
        self.prompt_output.write(
            "Authorization is required before remote mutation.\n"
            "Typing the exact phrase attests that the target is authorized, "
            "the firewall policy was reviewed, and management access is "
            "source-restricted.\n"
            "Type this exact phrase:\n"
            f"{phrase}\n"
            "> "
        )
        self.prompt_output.flush()
        response = self.authorization_input.readline()
        return AuthorizationDecision(
            authorized=response.rstrip("\r\n") == phrase,
        )


@dataclass(frozen=True)
class LocalGitRepository:
    repository_root: Path

    def _git(self, *arguments: str, check: bool = True) -> subprocess.CompletedProcess[bytes]:
        environment = os.environ.copy()
        environment["GIT_TERMINAL_PROMPT"] = "0"
        return subprocess.run(
            ["git", "-C", str(self.repository_root), *arguments],
            check=check,
            capture_output=True,
            env=environment,
            timeout=120,
        )

    def target_file_is_ignored(self, path: Path) -> bool:
        return (
            self._git(
                "check-ignore",
                "--quiet",
                "--",
                str(path),
                check=False,
            ).returncode
            == 0
        )

    def verify_candidate(
        self,
        commit: str,
        policy: dict[str, object],
    ) -> CandidateVerification:
        approved_ref = policy.get("approved_ref")
        protected_paths = policy.get("protected_paths")
        if not isinstance(approved_ref, str) or not isinstance(protected_paths, list):
            return CandidateVerification(
                passed=False,
                protected_hashes={},
                warnings=(),
                blocker="Deployment policy does not define candidate verification.",
            )
        if not all(
            isinstance(path, str)
            and path
            and not path.startswith("/")
            and ".." not in Path(path).parts
            and not any(character in path for character in ("*", "?", "[", "]"))
            for path in protected_paths
        ):
            return CandidateVerification(
                passed=False,
                protected_hashes={},
                warnings=(),
                blocker="Protected deployment paths must be exact repository paths.",
            )

        warnings: tuple[str, ...] = ()
        try:
            untracked = self._git(
                "status",
                "--porcelain",
                "--untracked-files=normal",
            ).stdout.splitlines()
            if any(line.startswith(b"?? ") for line in untracked):
                warnings = (
                    "Repository contains untracked files; they are not deployed.",
                )

            trusted_remote = policy.get("trusted_remote")
            trusted_repository = policy.get("trusted_repository")
            if trusted_remote is not None or trusted_repository is not None:
                if (
                    not isinstance(trusted_remote, str)
                    or not re.fullmatch(r"[A-Za-z0-9._-]+", trusted_remote)
                    or not isinstance(trusted_repository, str)
                    or not re.fullmatch(
                        r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+",
                        trusted_repository,
                    )
                    or approved_ref
                    != f"refs/remotes/{trusted_remote}/GSoC_2026"
                ):
                    return CandidateVerification(
                        passed=False,
                        protected_hashes={},
                        warnings=warnings,
                        blocker="Trusted upstream Git policy is malformed.",
                    )
                remote_url = self._git(
                    "config",
                    "--get",
                    f"remote.{trusted_remote}.url",
                    check=False,
                )
                accepted_urls = {
                    f"git@github.com:{trusted_repository}.git",
                    f"git@github.com:{trusted_repository}",
                    f"https://github.com/{trusted_repository}.git",
                    f"https://github.com/{trusted_repository}",
                    f"ssh://git@github.com/{trusted_repository}.git",
                    f"ssh://git@github.com/{trusted_repository}",
                }
                if (
                    remote_url.returncode
                    or remote_url.stdout.decode("utf-8").strip()
                    not in accepted_urls
                ):
                    return CandidateVerification(
                        passed=False,
                        protected_hashes={},
                        warnings=warnings,
                        blocker="Configured trusted upstream remote is invalid.",
                    )
                refreshed = self._git(
                    "-c",
                    "core.sshCommand=ssh -o BatchMode=yes",
                    "fetch",
                    "--quiet",
                    "--no-tags",
                    trusted_remote,
                    (
                        "+refs/heads/GSoC_2026:"
                        f"refs/remotes/{trusted_remote}/GSoC_2026"
                    ),
                    check=False,
                )
                if refreshed.returncode:
                    return CandidateVerification(
                        passed=False,
                        protected_hashes={},
                        warnings=warnings,
                        blocker="Trusted upstream deployment ref could not be refreshed.",
                    )

            if self._git("cat-file", "-e", f"{commit}^{{commit}}", check=False).returncode:
                return CandidateVerification(
                    passed=False,
                    protected_hashes={},
                    warnings=warnings,
                    blocker="Deployment commit does not exist in the local repository.",
                )
            if self._git("show-ref", "--verify", "--quiet", approved_ref, check=False).returncode:
                return CandidateVerification(
                    passed=False,
                    protected_hashes={},
                    warnings=warnings,
                    blocker="Approved deployment ref is unavailable locally.",
                )
            if self._git(
                "merge-base",
                "--is-ancestor",
                commit,
                approved_ref,
                check=False,
            ).returncode:
                return CandidateVerification(
                    passed=False,
                    protected_hashes={},
                    warnings=warnings,
                    blocker="Deployment commit is not reachable from the approved ref.",
                )

            protected_hashes: dict[str, str] = {}
            for protected_path in protected_paths:
                local_path = self.repository_root / protected_path
                if not local_path.is_file() or local_path.is_symlink():
                    return CandidateVerification(
                        passed=False,
                        protected_hashes={},
                        warnings=warnings,
                        blocker=f"Protected deployment path is missing: {protected_path}",
                    )
                status = self._git(
                    "status",
                    "--porcelain",
                    "--untracked-files=all",
                    "--",
                    protected_path,
                ).stdout
                if status.strip():
                    return CandidateVerification(
                        passed=False,
                        protected_hashes={},
                        warnings=warnings,
                        blocker=(
                            "Protected deployment path has staged, tracked, or "
                            f"untracked changes: {protected_path}"
                        ),
                    )
                committed = self._git(
                    "show",
                    f"{commit}:{protected_path}",
                    check=False,
                )
                if committed.returncode:
                    return CandidateVerification(
                        passed=False,
                        protected_hashes={},
                        warnings=warnings,
                        blocker=(
                            "Deployment commit does not contain protected path: "
                            f"{protected_path}"
                        ),
                    )
                local_content = local_path.read_bytes()
                if local_content != committed.stdout:
                    return CandidateVerification(
                        passed=False,
                        protected_hashes={},
                        warnings=warnings,
                        blocker=(
                            "Protected deployment path differs from deployment "
                            f"commit: {protected_path}"
                        ),
                    )
                protected_hashes[protected_path] = hashlib.sha256(
                    local_content
                ).hexdigest()

        except (OSError, UnicodeError, subprocess.SubprocessError):
            return CandidateVerification(
                passed=False,
                protected_hashes={},
                warnings=warnings,
                blocker="Local Git candidate verification malfunctioned.",
            )

        return CandidateVerification(
            passed=True,
            protected_hashes=protected_hashes,
            warnings=warnings,
            blocker=None,
        )


class GitHubApiError(RuntimeError):
    """Raised when trusted GitHub evidence cannot be retrieved safely."""


class GitHubPrerequisiteError(GitHubApiError):
    """Raised when the supported workstation lacks GitHub CLI access."""


@dataclass(frozen=True)
class GitHubCliActionsApi:
    executable: str = "gh"
    timeout_seconds: int = 30

    def _get(
        self,
        endpoint: str,
        fields: dict[str, str],
    ) -> dict[str, object]:
        if shutil.which(self.executable) is None:
            raise GitHubPrerequisiteError("GitHub CLI is unavailable")
        command = [
            self.executable,
            "api",
            "--method",
            "GET",
            "-H",
            "Accept: application/vnd.github+json",
            "-H",
            "X-GitHub-Api-Version: 2026-03-10",
            endpoint,
        ]
        for name, value in sorted(fields.items()):
            command.extend(("--raw-field", f"{name}={value}"))
        try:
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise GitHubApiError("GitHub API command malfunctioned") from error
        if completed.returncode != 0:
            raise GitHubApiError("GitHub API request did not complete")
        try:
            document = json.loads(completed.stdout)
        except json.JSONDecodeError as error:
            raise GitHubApiError("GitHub API returned malformed JSON") from error
        if not isinstance(document, dict):
            raise GitHubApiError("GitHub API returned an unexpected document")
        return document

    def list_workflow_runs(
        self,
        repository: str,
        workflow_path: str,
        event: str,
        head_sha: str,
        head_branch: str,
    ) -> list[dict[str, object]]:
        document = self._get(
            (
                f"/repos/{repository}/actions/workflows/"
                f"{Path(workflow_path).name}/runs"
            ),
            {
                "branch": head_branch,
                "event": event,
                "head_sha": head_sha,
                "per_page": "100",
            },
        )
        runs = document.get("workflow_runs")
        if not isinstance(runs, list) or not all(
            isinstance(run, dict) for run in runs
        ):
            raise GitHubApiError("GitHub API workflow runs are malformed")
        return runs

    def list_run_attempt_jobs(
        self,
        repository: str,
        run_id: int,
        run_attempt: int,
    ) -> list[dict[str, object]]:
        document = self._get(
            (
                f"/repos/{repository}/actions/runs/{run_id}/attempts/"
                f"{run_attempt}/jobs"
            ),
            {"per_page": "100"},
        )
        jobs = document.get("jobs")
        if not isinstance(jobs, list) or not all(
            isinstance(job, dict) for job in jobs
        ):
            raise GitHubApiError("GitHub API workflow jobs are malformed")
        return jobs


@dataclass(frozen=True)
class TrustedGitHubActions:
    api: GitHubActionsApi

    @staticmethod
    def _blocked(message: str) -> CiVerification:
        return CiVerification(
            passed=False,
            proof={},
            blocker=message,
            outcome="BLOCKED",
        )

    def verify(
        self,
        commit: str,
        policy: dict[str, object],
    ) -> CiVerification:
        repository = policy.get("trusted_repository")
        ci = policy.get("ci")
        if not isinstance(repository, str) or not isinstance(ci, dict):
            return self._blocked("Trusted CI policy is unavailable.")
        workflow_path = ci.get("workflow_path")
        event = ci.get("event")
        head_branch = ci.get("head_branch")
        required_jobs = ci.get("required_jobs")
        if (
            not isinstance(workflow_path, str)
            or not isinstance(event, str)
            or not isinstance(head_branch, str)
            or not isinstance(required_jobs, list)
            or not all(isinstance(name, str) for name in required_jobs)
        ):
            return self._blocked("Trusted CI policy is malformed.")

        try:
            runs = self.api.list_workflow_runs(
                repository,
                workflow_path,
                event,
                commit,
                head_branch,
            )
        except GitHubPrerequisiteError:
            return self._blocked(
                "Install and authenticate GitHub CLI for read-only Actions proof."
            )
        except GitHubApiError:
            return CiVerification(
                passed=False,
                proof={},
                blocker="Trusted GitHub Actions evidence retrieval malfunctioned.",
                outcome="ERROR",
            )
        if not runs:
            return self._blocked(
                "No trusted upstream push run exists for the exact commit."
            )

        def run_sort_key(run: dict[str, object]) -> tuple[str, int]:
            run_identifier = run.get("id")
            return (
                str(run.get("created_at", "")),
                run_identifier if isinstance(run_identifier, int) else -1,
            )

        selected = max(runs, key=run_sort_key)

        selected_repository = selected.get("repository")
        repository_name = (
            selected_repository.get("full_name")
            if isinstance(selected_repository, dict)
            else None
        )
        run_path = selected.get("path")
        normalized_path = (
            run_path.split("@", 1)[0]
            if isinstance(run_path, str)
            else None
        )
        expected_values = {
            "repository": (repository_name, repository),
            "workflow": (normalized_path, workflow_path),
            "event": (selected.get("event"), event),
            "head SHA": (selected.get("head_sha"), commit),
            "head branch": (selected.get("head_branch"), head_branch),
        }
        if any(observed != expected for observed, expected in expected_values.values()):
            return self._blocked(
                "Newest exact-commit workflow evidence has an untrusted identity."
            )
        if (
            selected.get("status") != "completed"
            or selected.get("conclusion") != "success"
        ):
            return self._blocked(
                "Newest exact-commit push workflow is not successfully completed."
            )

        run_id = selected.get("id")
        workflow_id = selected.get("workflow_id")
        run_attempt = selected.get("run_attempt")
        timestamps = {
            "created_at": selected.get("created_at"),
            "run_started_at": selected.get("run_started_at"),
            "updated_at": selected.get("updated_at"),
        }
        html_url = selected.get("html_url")
        if (
            not isinstance(run_id, int)
            or run_id < 1
            or not isinstance(workflow_id, int)
            or workflow_id < 1
            or not isinstance(run_attempt, int)
            or run_attempt < 1
            or not all(
                isinstance(value, str) and value
                for value in timestamps.values()
            )
            or html_url
            != f"https://github.com/{repository}/actions/runs/{run_id}"
        ):
            return CiVerification(
                passed=False,
                proof={},
                blocker="Trusted GitHub Actions run evidence is malformed.",
                outcome="ERROR",
            )

        try:
            jobs = self.api.list_run_attempt_jobs(
                repository,
                run_id,
                run_attempt,
            )
        except GitHubPrerequisiteError:
            return self._blocked(
                "Install and authenticate GitHub CLI for read-only Actions proof."
            )
        except GitHubApiError:
            return CiVerification(
                passed=False,
                proof={},
                blocker="Trusted GitHub Actions job evidence retrieval malfunctioned.",
                outcome="ERROR",
            )

        jobs_by_name: dict[str, dict[str, object]] = {}
        for job in jobs:
            name_value = job.get("name")
            if not isinstance(name_value, str):
                return self._blocked(
                    "Latest workflow attempt has duplicate or dynamic job names."
                )
            name = name_value
            if name in jobs_by_name:
                return self._blocked(
                    "Latest workflow attempt has duplicate or dynamic job names."
                )
            jobs_by_name[name] = job
        if set(jobs_by_name) != set(required_jobs):
            return self._blocked(
                "Latest workflow attempt does not contain exactly the required jobs."
            )

        proof_jobs: list[dict[str, object]] = []
        for name in required_jobs:
            job = jobs_by_name[name]
            started_at = job.get("started_at")
            completed_at = job.get("completed_at")
            if (
                job.get("head_sha") != commit
                or job.get("status") != "completed"
                or job.get("conclusion") != "success"
                or not isinstance(started_at, str)
                or not started_at
                or not isinstance(completed_at, str)
                or not completed_at
            ):
                return self._blocked(
                    "Latest workflow attempt has a non-successful required job."
                )
            proof_jobs.append(
                {
                    "name": name,
                    "status": "completed",
                    "conclusion": "success",
                    "started_at": started_at,
                    "completed_at": completed_at,
                    "run_attempt": run_attempt,
                }
            )

        proof: dict[str, object] = {
            "schema_version": CI_PROOF_SCHEMA_VERSION,
            "repository": repository,
            "workflow_path": workflow_path,
            "workflow_id": workflow_id,
            "run_id": run_id,
            "run_attempt": run_attempt,
            "head_sha": commit,
            "head_branch": head_branch,
            "event": event,
            "status": "completed",
            "conclusion": "success",
            **timestamps,
            "jobs": proof_jobs,
            "url": html_url,
        }
        return CiVerification(
            passed=True,
            proof=proof,
            blocker=None,
            outcome="PASS",
        )


@dataclass(frozen=True)
class SystemClock:
    def now(self) -> datetime:
        return datetime.now(timezone.utc)


@dataclass(frozen=True)
class SystemRandomSource:
    def run_suffix(self) -> str:
        return secrets.token_hex(3)


@dataclass(frozen=True)
class SystemSshProbeTransport:
    probe_path: Path
    ssh_executable: str | Path = "ssh"
    timeout_seconds: int = 45

    def collect(
        self,
        configuration: TargetConfiguration,
        commit: str,
        policy: dict[str, object],
    ) -> RemoteProbeExecution:
        trusted_repository = policy.get("trusted_repository")
        if not isinstance(trusted_repository, str):
            raise OSError("deployment policy lacks a trusted repository")
        request = {
            "schema_version": REMOTE_PREFLIGHT_SCHEMA_VERSION,
            "target_alias": configuration.target_alias,
            "deployment_commit": commit,
            "deploy_dir": configuration.vps_deploy_dir,
            "project_name": configuration.vps_project_name,
            "trusted_repository": trusted_repository,
            "memory_limit": configuration.field_tarpit_memory_limit,
            "reference_epoch": int(datetime.now(timezone.utc).timestamp()),
        }
        encoded_request = base64.urlsafe_b64encode(
            json.dumps(
                request,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        ).decode("ascii")
        probe = self.probe_path.read_bytes()
        environment = os.environ.copy()
        environment.update(
            {
                "GIT_TERMINAL_PROMPT": "0",
                "LC_ALL": "C",
            }
        )
        completed = subprocess.run(
            [
                str(self.ssh_executable),
                "-o",
                "BatchMode=yes",
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "StrictHostKeyChecking=yes",
                "-o",
                "ConnectTimeout=10",
                "-p",
                str(configuration.vps_ssh_port),
                "-i",
                str(configuration.vps_ssh_key),
                f"{configuration.vps_user}@{configuration.vps_host}",
                "python3",
                "-",
                encoded_request,
            ],
            input=probe,
            capture_output=True,
            check=False,
            env=environment,
            timeout=self.timeout_seconds,
        )
        return RemoteProbeExecution(
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )


@dataclass(frozen=True)
class SystemSshDeploymentTransport:
    deployment_program_path: Path
    ssh_executable: str | Path = "ssh"
    timeout_seconds: int = 1800

    def execute(
        self,
        configuration: TargetConfiguration,
        commit: str,
        policy: dict[str, object],
        preflight: dict[str, object],
        run_id: str,
    ) -> RemoteDeploymentExecution:
        trusted_repository = policy.get("trusted_repository")
        approved_ref = policy.get("approved_ref")
        compose_files = policy.get("supported_compose_files")
        starting_state = preflight.get("starting_state")
        managed_checkout_commit = preflight.get(
            "managed_checkout_commit"
        )
        prior_evidence_commit = preflight.get("prior_evidence_commit")
        interrupted_redeployment = preflight.get(
            "interrupted_redeployment"
        )
        if (
            not isinstance(trusted_repository, str)
            or not isinstance(approved_ref, str)
            or not isinstance(compose_files, list)
            or not all(isinstance(path, str) for path in compose_files)
            or starting_state
            not in {"INITIAL_DEPLOYMENT", "MANAGED_REDEPLOYMENT"}
            or type(interrupted_redeployment) is not bool
            or (
                starting_state == "INITIAL_DEPLOYMENT"
                and (
                    managed_checkout_commit is not None
                    or prior_evidence_commit is not None
                    or interrupted_redeployment
                )
            )
            or (
                starting_state == "MANAGED_REDEPLOYMENT"
                and (
                    not isinstance(managed_checkout_commit, str)
                    or FULL_SHA_PATTERN.fullmatch(
                        managed_checkout_commit
                    )
                    is None
                    or not isinstance(prior_evidence_commit, str)
                    or FULL_SHA_PATTERN.fullmatch(prior_evidence_commit)
                    is None
                    or interrupted_redeployment
                    != (
                        managed_checkout_commit
                        != prior_evidence_commit
                    )
                )
            )
        ):
            raise OSError("deployment policy or preflight evidence is incomplete")
        approved_branch = approved_ref.rsplit("/", 1)[-1]
        request = {
            "schema_version": 1,
            "run_id": run_id,
            "target_alias": configuration.target_alias,
            "deployment_commit": commit,
            "deploy_dir": configuration.vps_deploy_dir,
            "project_name": configuration.vps_project_name,
            "trusted_repository": trusted_repository,
            "approved_branch": approved_branch,
            "starting_state": starting_state,
            "managed_checkout_commit": managed_checkout_commit,
            "prior_evidence_commit": prior_evidence_commit,
            "interrupted_redeployment": interrupted_redeployment,
            "compose_files": compose_files,
            "cpu_limit": configuration.field_tarpit_cpu_limit,
            "memory_limit": configuration.field_tarpit_memory_limit,
        }
        encoded_request = base64.urlsafe_b64encode(
            json.dumps(
                request,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        ).decode("ascii")
        program = self.deployment_program_path.read_bytes()
        environment = os.environ.copy()
        environment.update(
            {
                "GIT_TERMINAL_PROMPT": "0",
                "LC_ALL": "C",
            }
        )
        completed = subprocess.run(
            [
                str(self.ssh_executable),
                "-o",
                "BatchMode=yes",
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "StrictHostKeyChecking=yes",
                "-o",
                "ConnectTimeout=10",
                "-p",
                str(configuration.vps_ssh_port),
                "-i",
                str(configuration.vps_ssh_key),
                f"{configuration.vps_user}@{configuration.vps_host}",
                "python3",
                "-",
                encoded_request,
            ],
            input=program,
            capture_output=True,
            check=False,
            env=environment,
            timeout=self.timeout_seconds,
        )
        return RemoteDeploymentExecution(
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )


@dataclass(frozen=True)
class SystemSshRuntimeTransport:
    runtime_program_path: Path
    ssh_executable: str | Path = "ssh"
    timeout_seconds: int = 180

    def _execute(
        self,
        configuration: TargetConfiguration,
        commit: str,
        run_id: str,
        action: str,
        expected_image_ids: dict[str, str],
    ) -> RemoteRuntimeExecution:
        request = {
            "schema_version": HEALTH_AND_PORTS_SCHEMA_VERSION,
            "action": action,
            "run_id": run_id,
            "target_alias": configuration.target_alias,
            "deployment_commit": commit,
            "deploy_dir": configuration.vps_deploy_dir,
            "project_name": configuration.vps_project_name,
            "expected_image_ids": expected_image_ids,
        }
        encoded_request = base64.urlsafe_b64encode(
            json.dumps(
                request,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        ).decode("ascii")
        program = self.runtime_program_path.read_bytes()
        environment = os.environ.copy()
        environment.update(
            {
                "GIT_TERMINAL_PROMPT": "0",
                "LC_ALL": "C",
            }
        )
        completed = subprocess.run(
            [
                str(self.ssh_executable),
                "-o",
                "BatchMode=yes",
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "StrictHostKeyChecking=yes",
                "-o",
                "ConnectTimeout=10",
                "-p",
                str(configuration.vps_ssh_port),
                "-i",
                str(configuration.vps_ssh_key),
                f"{configuration.vps_user}@{configuration.vps_host}",
                "python3",
                "-",
                encoded_request,
            ],
            input=program,
            capture_output=True,
            check=False,
            env=environment,
            timeout=self.timeout_seconds,
        )
        return RemoteRuntimeExecution(
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )

    def inspect(
        self,
        configuration: TargetConfiguration,
        commit: str,
        expected_image_ids: dict[str, str],
        run_id: str,
    ) -> RemoteRuntimeExecution:
        return self._execute(
            configuration,
            commit,
            run_id,
            "VERIFY",
            expected_image_ids,
        )

    def stop(
        self,
        configuration: TargetConfiguration,
        commit: str,
        run_id: str,
    ) -> bool:
        execution = self._execute(
            configuration,
            commit,
            run_id,
            "STOP",
            {},
        )
        if (
            execution.returncode != 0
            or len(execution.stdout) > 64 * 1024
        ):
            return False
        try:
            evidence = json.loads(execution.stdout)
        except (UnicodeError, json.JSONDecodeError):
            return False
        return (
            isinstance(evidence, dict)
            and set(evidence)
            == {
                "schema_version",
                "action",
                "run_id",
                "target_alias",
                "deployment_commit",
                "result",
                "blocker",
                "field_services_running",
            }
            and evidence["schema_version"]
            == HEALTH_AND_PORTS_SCHEMA_VERSION
            and evidence["action"] == "STOP"
            and evidence["run_id"] == run_id
            and evidence["target_alias"] == configuration.target_alias
            and evidence["deployment_commit"] == commit
            and evidence["result"] == "PASS"
            and evidence["blocker"] is None
            and evidence["field_services_running"] is False
        )


@dataclass(frozen=True)
class SystemTcpPortProbe:
    timeout_seconds: float = 5.0

    def _observe_one(
        self,
        addresses: tuple[tuple[int, tuple[object, ...]], ...],
        port: int,
    ) -> bool:
        for family, address in addresses:
            destination = (address[0], port, *address[2:])
            try:
                with socket.socket(family, socket.SOCK_STREAM) as connection:
                    connection.settimeout(self.timeout_seconds)
                    connection.connect(destination)
                return True
            except OSError:
                continue
        return False

    def observe(
        self,
        host: str,
        ports: tuple[int, ...],
    ) -> dict[int, bool]:
        resolved = socket.getaddrinfo(
            host,
            0,
            type=socket.SOCK_STREAM,
        )
        addresses = tuple(
            dict.fromkeys(
                (family, address)
                for family, _type, _protocol, _name, address in resolved
            )
        )
        if not addresses:
            raise OSError("target address could not be resolved")
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=len(ports)
        ) as executor:
            futures = {
                port: executor.submit(
                    self._observe_one,
                    addresses,
                    port,
                )
                for port in ports
            }
            return {
                port: futures[port].result()
                for port in ports
            }


def _remote_preflight_evidence_is_valid(
    evidence: object,
    configuration: TargetConfiguration,
    commit: str,
) -> bool:
    if not isinstance(evidence, dict) or set(evidence) != {
        "schema_version",
        "target_alias",
        "deployment_commit",
        "checked_utc",
        "starting_state",
        "managed_checkout_commit",
        "prior_evidence_commit",
        "interrupted_redeployment",
        "result",
        "checks",
    }:
        return False
    if (
        type(evidence["schema_version"]) is not int
        or evidence["schema_version"] != REMOTE_PREFLIGHT_SCHEMA_VERSION
        or evidence["target_alias"] != configuration.target_alias
        or evidence["deployment_commit"] != commit
        or evidence["starting_state"]
        not in {"INITIAL_DEPLOYMENT", "MANAGED_REDEPLOYMENT", "UNSUPPORTED"}
        or evidence["result"] not in {"PASS", "BLOCKED"}
        or (
            evidence["managed_checkout_commit"] is not None
            and (
                not isinstance(evidence["managed_checkout_commit"], str)
                or re.fullmatch(
                    r"[0-9a-f]{40}",
                    evidence["managed_checkout_commit"],
                )
                is None
            )
        )
        or (
            evidence["prior_evidence_commit"] is not None
            and (
                not isinstance(evidence["prior_evidence_commit"], str)
                or re.fullmatch(
                    r"[0-9a-f]{40}",
                    evidence["prior_evidence_commit"],
                )
                is None
            )
        )
        or type(evidence["interrupted_redeployment"]) is not bool
        or not isinstance(evidence["checked_utc"], str)
        or not isinstance(evidence["checks"], list)
        or not 1 <= len(evidence["checks"]) <= 64
    ):
        return False
    try:
        checked = datetime.fromisoformat(
            evidence["checked_utc"].replace("Z", "+00:00")
        )
    except ValueError:
        return False
    if checked.tzinfo is None:
        return False

    starting_state = evidence["starting_state"]
    managed_checkout_commit = evidence["managed_checkout_commit"]
    prior_evidence_commit = evidence["prior_evidence_commit"]
    interrupted_redeployment = evidence["interrupted_redeployment"]
    if starting_state in {"INITIAL_DEPLOYMENT", "UNSUPPORTED"}:
        if (
            managed_checkout_commit is not None
            or prior_evidence_commit is not None
            or interrupted_redeployment
        ):
            return False
    elif interrupted_redeployment:
        if (
            managed_checkout_commit is None
            or prior_evidence_commit is None
            or managed_checkout_commit == prior_evidence_commit
        ):
            return False
    elif (
        evidence["result"] == "PASS"
        and (
            managed_checkout_commit is None
            or managed_checkout_commit != prior_evidence_commit
        )
    ):
        return False

    check_ids: set[str] = set()
    statuses: list[str] = []
    for check in evidence["checks"]:
        if not isinstance(check, dict) or set(check) != {
            "id",
            "status",
            "summary",
        }:
            return False
        check_id = check["id"]
        status_value = check["status"]
        summary = check["summary"]
        if (
            not isinstance(check_id, str)
            or re.fullmatch(r"[a-z][a-z0-9_]{0,63}", check_id) is None
            or check_id in check_ids
            or status_value not in {"PASS", "WARNING", "BLOCKER"}
            or not isinstance(summary, str)
            or not 1 <= len(summary) <= 240
        ):
            return False
        check_ids.add(check_id)
        statuses.append(status_value)

    if evidence["result"] == "PASS":
        return (
            evidence["starting_state"]
            in {"INITIAL_DEPLOYMENT", "MANAGED_REDEPLOYMENT"}
            and "BLOCKER" not in statuses
        )
    return "BLOCKER" in statuses


@dataclass(frozen=True)
class SshRemotePreflight:
    transport: RemoteProbeCapabilities

    def preflight(
        self,
        configuration: TargetConfiguration,
        commit: str,
        policy: dict[str, object],
    ) -> RemotePreflightVerification:
        try:
            execution = self.transport.collect(configuration, commit, policy)
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return RemotePreflightVerification(
                passed=False,
                evidence={},
                blocker="Remote preflight transport malfunctioned.",
                outcome="ERROR",
            )
        if execution.returncode != 0:
            return RemotePreflightVerification(
                passed=False,
                evidence={},
                blocker="Remote preflight transport malfunctioned.",
                outcome="ERROR",
            )
        try:
            if len(execution.stdout) > 256 * 1024:
                raise ValueError
            evidence = json.loads(execution.stdout.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError, ValueError):
            return RemotePreflightVerification(
                passed=False,
                evidence={},
                blocker="Remote preflight returned malformed evidence.",
                outcome="ERROR",
            )
        if not _remote_preflight_evidence_is_valid(
            evidence,
            configuration,
            commit,
        ):
            return RemotePreflightVerification(
                passed=False,
                evidence={},
                blocker="Remote preflight returned malformed evidence.",
                outcome="ERROR",
            )
        passed = evidence["result"] == "PASS"
        return RemotePreflightVerification(
            passed=passed,
            evidence=evidence,
            blocker=(
                None
                if passed
                else "Remote preflight reported a policy or prerequisite blocker."
            ),
            outcome="PASS" if passed else "BLOCKED",
        )


def _safe_evidence_text(value: object, maximum: int = 240) -> bool:
    return (
        isinstance(value, str)
        and 1 <= len(value) <= maximum
        and all(
            ord(character) >= 0x20 and ord(character) != 0x7F
            for character in value
        )
    )


def _compose_config_evidence_is_valid(
    document: object,
    configuration: TargetConfiguration,
    commit: str,
    policy: dict[str, object],
) -> bool:
    if not isinstance(document, dict) or set(document) != {
        "schema_version",
        "deployment_commit",
        "project_name",
        "platform",
        "rendered_config_sha256",
        "services",
        "volumes",
    }:
        return False
    services = document["services"]
    if (
        document["schema_version"] != COMPOSE_CONFIG_SCHEMA_VERSION
        or document["deployment_commit"] != commit
        or document["project_name"] != configuration.vps_project_name
        or document["platform"] != "linux/amd64"
        or not isinstance(document["rendered_config_sha256"], str)
        or re.fullmatch(
            r"[0-9a-f]{64}",
            document["rendered_config_sha256"],
        )
        is None
        or document["volumes"]
        != ["grafana-storage", "prometheus-data", "tarpit-sock"]
        or not isinstance(services, list)
        or len(services) != 6
    ):
        return False
    field_build = policy.get("field_build")
    if not isinstance(field_build, dict):
        return False
    compose_images = field_build.get("compose_images")
    if not isinstance(compose_images, dict):
        return False
    expected_sources = {
        "cadvisor": ("PINNED_IMAGE", compose_images.get("cadvisor")),
        "grafana": ("PINNED_IMAGE", compose_images.get("grafana")),
        "mqtt_pit": ("BUILD", "docker/tarpits/Dockerfile"),
        "prometheus": ("PINNED_IMAGE", compose_images.get("prometheus")),
        "prometheus-exporter": (
            "BUILD",
            "docker/prometheus/Dockerfile",
        ),
        "telnet_pit": ("BUILD", "docker/tarpits/Dockerfile"),
    }
    expected_ports = {
        "cadvisor": ("127.0.0.1", 8081, 8080),
        "grafana": ("127.0.0.1", 3000, 3000),
        "mqtt_pit": ("0.0.0.0", 1883, 1883),
        "prometheus": ("127.0.0.1", 9090, 9090),
        "prometheus-exporter": ("127.0.0.1", 9101, 9101),
        "telnet_pit": ("0.0.0.0", 23, 23),
    }
    expected_names = list(expected_sources)
    if [service.get("name") for service in services] != expected_names:
        return False
    for service in services:
        if not isinstance(service, dict) or set(service) != {
            "name",
            "source_type",
            "source",
            "platform",
            "ports",
            "restart",
            "logging_driver",
            "cpu_limit",
            "memory_limit_bytes",
            "privileged",
            "volumes",
        }:
            return False
        name = service["name"]
        source_type, source = expected_sources[name]
        ports = service["ports"]
        if (
            service["source_type"] != source_type
            or service["source"] != source
            or service["platform"] != "linux/amd64"
            or service["restart"] != "unless-stopped"
            or service["logging_driver"]
            != ("none" if name in {"mqtt_pit", "telnet_pit"} else "json-file")
            or service["privileged"] != (name == "cadvisor")
            or not isinstance(ports, list)
            or len(ports) != 1
        ):
            return False
        port = ports[0]
        if (
            not isinstance(port, dict)
            or set(port) != {"host_ip", "published", "target", "protocol"}
            or (
                port["host_ip"],
                port["published"],
                port["target"],
            )
            != expected_ports[name]
            or port["protocol"] != "tcp"
        ):
            return False
        is_tarpit = name in {"mqtt_pit", "telnet_pit"}
        cpu_limit = service["cpu_limit"]
        memory_limit = service["memory_limit_bytes"]
        if is_tarpit:
            try:
                cpu_matches = (
                    isinstance(cpu_limit, str)
                    and Decimal(cpu_limit)
                    == Decimal(configuration.field_tarpit_cpu_limit)
                )
            except InvalidOperation:
                return False
            if not cpu_matches or (
                configuration.field_tarpit_memory_limit is not None
                and (
                    type(memory_limit) is not int
                    or memory_limit <= 0
                )
            ) or (
                configuration.field_tarpit_memory_limit is None
                and memory_limit is not None
            ):
                return False
        elif cpu_limit is not None or memory_limit is not None:
            return False
        volumes = service["volumes"]
        if not isinstance(volumes, list) or len(volumes) > 8:
            return False
        for volume in volumes:
            if (
                not isinstance(volume, dict)
                or set(volume) != {"type", "target", "read_only"}
                or volume["type"] not in {"bind", "volume"}
                or not isinstance(volume["target"], str)
                or re.fullmatch(r"/[A-Za-z0-9._/-]+", volume["target"]) is None
                or type(volume["read_only"]) is not bool
            ):
                return False
    return True


def _image_ids_are_valid(
    value: object,
    *,
    require_all: bool,
) -> bool:
    expected = {
        "cadvisor",
        "grafana",
        "mqtt_pit",
        "prometheus",
        "prometheus-exporter",
        "telnet_pit",
    }
    if not isinstance(value, dict):
        return False
    if (require_all and set(value) != expected) or (
        not require_all and not set(value).issubset(expected)
    ):
        return False
    return all(
        isinstance(image_id, str)
        and re.fullmatch(r"sha256:[0-9a-f]{64}", image_id) is not None
        for image_id in value.values()
    )


def _volume_names_are_valid(value: object) -> bool:
    return (
        isinstance(value, list)
        and len(value) <= 32
        and len(set(value)) == len(value)
        and all(
            isinstance(name, str)
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", name)
            is not None
            for name in value
        )
    )


def _deployment_manifest_evidence_is_valid(
    document: object,
    configuration: TargetConfiguration,
    commit: str,
    policy: dict[str, object],
    preflight: dict[str, object],
    run_id: str,
    result: str,
    compose_config: dict[str, object],
) -> bool:
    if not isinstance(document, dict) or set(document) != {
        "schema_version",
        "run_id",
        "target_alias",
        "deployment_commit",
        "repository_commit",
        "compose_project_name",
        "trusted_repository",
        "approved_branch",
        "starting_state",
        "deployed_utc",
        "platform",
        "head_verified",
        "worktree_clean",
        "docker_version",
        "compose_version",
        "rendered_compose_sha256",
        "pinned_inputs",
        "service_image_ids",
        "volume_names",
        "prior_deployment",
        "cleanup",
        "result",
    }:
        return False
    field_build = policy.get("field_build")
    if not isinstance(field_build, dict):
        return False
    base_images = field_build.get("base_images")
    compose_images = field_build.get("compose_images")
    if not isinstance(base_images, list) or not isinstance(compose_images, dict):
        return False
    expected_pinned_inputs = sorted([*base_images, *compose_images.values()])
    if (
        document["schema_version"] != DEPLOYMENT_MANIFEST_SCHEMA_VERSION
        or document["run_id"] != run_id
        or document["target_alias"] != configuration.target_alias
        or document["deployment_commit"] != commit
        or document["repository_commit"] != commit
        or document["compose_project_name"] != configuration.vps_project_name
        or document["trusted_repository"] != policy.get("trusted_repository")
        or document["approved_branch"] != "GSoC_2026"
        or document["starting_state"] != preflight.get("starting_state")
        or document["platform"] != "linux/amd64"
        or document["head_verified"] is not True
        or document["worktree_clean"] is not True
        or not _safe_evidence_text(document["docker_version"], 100)
        or not _safe_evidence_text(document["compose_version"], 100)
        or document["rendered_compose_sha256"]
        != compose_config.get("rendered_config_sha256")
        or document["pinned_inputs"] != expected_pinned_inputs
        or not _image_ids_are_valid(
            document["service_image_ids"],
            require_all=result == "PASS",
        )
        or not _volume_names_are_valid(document["volume_names"])
        or document["result"] != result
    ):
        return False
    try:
        deployed = datetime.fromisoformat(
            str(document["deployed_utc"]).replace("Z", "+00:00")
        )
    except ValueError:
        return False
    if deployed.tzinfo is None:
        return False
    prior = document["prior_deployment"]
    if not isinstance(prior, dict) or set(prior) != {
        "commit",
        "service_image_ids",
        "volume_names",
    }:
        return False
    prior_commit = prior["commit"]
    if (
        prior_commit is not None
        and (
            not isinstance(prior_commit, str)
            or FULL_SHA_PATTERN.fullmatch(prior_commit) is None
        )
    ):
        return False
    if not _image_ids_are_valid(
        prior["service_image_ids"],
        require_all=False,
    ) or not _volume_names_are_valid(prior["volume_names"]):
        return False
    cleanup = document["cleanup"]
    if (
        not isinstance(cleanup, dict)
        or set(cleanup) != {"attempted", "succeeded"}
        or type(cleanup["attempted"]) is not bool
        or (
            cleanup["succeeded"] is not None
            and type(cleanup["succeeded"]) is not bool
        )
        or (
            not cleanup["attempted"]
            and cleanup["succeeded"] is not None
        )
        or (
            cleanup["attempted"]
            and type(cleanup["succeeded"]) is not bool
        )
    ):
        return False
    return not (
        result == "PASS"
        and (
            cleanup["attempted"]
            or cleanup["succeeded"] is not None
        )
    )


def _remote_deployment_evidence_is_valid(
    evidence: object,
    configuration: TargetConfiguration,
    commit: str,
    policy: dict[str, object],
    preflight: dict[str, object],
    run_id: str,
) -> bool:
    if not isinstance(evidence, dict) or set(evidence) != {
        "schema_version",
        "run_id",
        "target_alias",
        "deployment_commit",
        "result",
        "blocker",
        "remote_mutation_occurred",
        "field_services_running",
        "compose_config",
        "deployment_manifest",
    }:
        return False
    result = evidence["result"]
    blocker = evidence["blocker"]
    compose_config = evidence["compose_config"]
    deployment_manifest = evidence["deployment_manifest"]
    if (
        evidence["schema_version"] != 1
        or evidence["run_id"] != run_id
        or evidence["target_alias"] != configuration.target_alias
        or evidence["deployment_commit"] != commit
        or result not in {"PASS", "BLOCKED", "FAIL", "INCONCLUSIVE", "ERROR"}
        or type(evidence["remote_mutation_occurred"]) is not bool
        or type(evidence["field_services_running"]) is not bool
        or not isinstance(compose_config, dict)
        or not isinstance(deployment_manifest, dict)
    ):
        return False
    if result == "PASS":
        return (
            blocker is None
            and evidence["remote_mutation_occurred"]
            and evidence["field_services_running"]
            and _compose_config_evidence_is_valid(
                compose_config,
                configuration,
                commit,
                policy,
            )
            and _deployment_manifest_evidence_is_valid(
                deployment_manifest,
                configuration,
                commit,
                policy,
                preflight,
                run_id,
                result,
                compose_config,
            )
        )
    if not _safe_evidence_text(blocker):
        return False
    if compose_config and not _compose_config_evidence_is_valid(
        compose_config,
        configuration,
        commit,
        policy,
    ):
        return False
    return not deployment_manifest or _deployment_manifest_evidence_is_valid(
        deployment_manifest,
        configuration,
        commit,
        policy,
        preflight,
        run_id,
        result,
        compose_config,
    )


@dataclass(frozen=True)
class SshExactSourceDeployment:
    transport: RemoteDeploymentTransportCapabilities

    @staticmethod
    def _malfunction() -> RemoteDeploymentVerification:
        return RemoteDeploymentVerification(
            passed=False,
            outcome="ERROR",
            blocker=(
                "Remote deployment transport or evidence collection malfunctioned; "
                "inspect the authorized VPS and stop the field project if needed."
            ),
            remote_mutation_occurred=True,
            field_services_running=True,
            compose_config={},
            deployment_manifest={},
        )

    def deploy(
        self,
        configuration: TargetConfiguration,
        commit: str,
        policy: dict[str, object],
        preflight: dict[str, object],
        run_id: str,
    ) -> RemoteDeploymentVerification:
        try:
            execution = self.transport.execute(
                configuration,
                commit,
                policy,
                preflight,
                run_id,
            )
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return self._malfunction()
        if execution.returncode != 0:
            return self._malfunction()
        try:
            if len(execution.stdout) > 1024 * 1024:
                raise ValueError
            evidence = json.loads(execution.stdout.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError, ValueError):
            return self._malfunction()
        if not _remote_deployment_evidence_is_valid(
            evidence,
            configuration,
            commit,
            policy,
            preflight,
            run_id,
        ):
            return self._malfunction()
        result = evidence["result"]
        return RemoteDeploymentVerification(
            passed=result == "PASS",
            outcome=result,
            blocker=evidence["blocker"],
            remote_mutation_occurred=evidence["remote_mutation_occurred"],
            field_services_running=evidence["field_services_running"],
            compose_config=evidence["compose_config"],
            deployment_manifest=evidence["deployment_manifest"],
        )


RUNTIME_SERVICES = (
    "cadvisor",
    "grafana",
    "mqtt_pit",
    "prometheus",
    "prometheus-exporter",
    "telnet_pit",
)
RUNTIME_BINDINGS = {
    "cadvisor": (8080, 8081, "LOOPBACK"),
    "grafana": (3000, 3000, "LOOPBACK"),
    "mqtt_pit": (1883, 1883, "PUBLIC"),
    "prometheus": (9090, 9090, "LOOPBACK"),
    "prometheus-exporter": (9101, 9101, "LOOPBACK"),
    "telnet_pit": (23, 23, "PUBLIC"),
}
MANAGEMENT_ENDPOINTS = {
    "cadvisor": 8081,
    "grafana": 3000,
    "prometheus": 9090,
    "prometheus-exporter": 9101,
}
PUBLIC_PORTS = (23, 1883)
PRIVATE_PORTS = (3000, 8081, 9090, 9101)
RUNTIME_PORTS = (*PUBLIC_PORTS, *PRIVATE_PORTS)


def _runtime_service_is_valid(value: object) -> bool:
    return (
        isinstance(value, dict)
        and set(value)
        == {
            "name",
            "state",
            "health",
            "restart_count",
            "oom_killed",
            "image_id_verified",
        }
        and value["name"] in RUNTIME_SERVICES
        and value["state"] in {"RUNNING", "STOPPED", "EXITED", "UNKNOWN"}
        and value["health"]
        in {
            "HEALTHY",
            "UNHEALTHY",
            "STARTING",
            "NOT_CONFIGURED",
            "UNKNOWN",
        }
        and type(value["restart_count"]) is int
        and value["restart_count"] >= 0
        and type(value["oom_killed"]) is bool
        and type(value["image_id_verified"]) is bool
    )


def _runtime_binding_is_valid(value: object) -> bool:
    return (
        isinstance(value, dict)
        and set(value)
        == {
            "service",
            "container_port",
            "host_port",
            "scope",
            "result",
        }
        and value["service"] in RUNTIME_SERVICES
        and type(value["container_port"]) is int
        and 1 <= value["container_port"] <= 65535
        and type(value["host_port"]) is int
        and 1 <= value["host_port"] <= 65535
        and value["scope"] in {"PUBLIC", "LOOPBACK"}
        and value["result"] in {"PASS", "FAIL"}
    )


def _management_endpoint_is_valid(value: object) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == {"service", "port", "result"}
        and value["service"] in MANAGEMENT_ENDPOINTS
        and type(value["port"]) is int
        and value["port"] in PRIVATE_PORTS
        and value["result"] in {"READY", "NOT_READY"}
    )


def _remote_runtime_evidence_is_valid(
    evidence: object,
    configuration: TargetConfiguration,
    commit: str,
    run_id: str,
) -> bool:
    if not isinstance(evidence, dict) or set(evidence) != {
        "schema_version",
        "run_id",
        "target_alias",
        "deployment_commit",
        "checked_utc",
        "result",
        "blocker",
        "field_services_running",
        "services",
        "bindings",
        "management_endpoints",
    }:
        return False
    if (
        evidence["schema_version"] != 1
        or evidence["run_id"] != run_id
        or evidence["target_alias"] != configuration.target_alias
        or evidence["deployment_commit"] != commit
        or evidence["result"]
        not in {"PASS", "BLOCKED", "FAIL", "INCONCLUSIVE", "ERROR"}
        or type(evidence["field_services_running"]) is not bool
        or not isinstance(evidence["checked_utc"], str)
        or not isinstance(evidence["services"], list)
        or len(evidence["services"]) > len(RUNTIME_SERVICES)
        or not all(
            _runtime_service_is_valid(service)
            for service in evidence["services"]
        )
        or not isinstance(evidence["bindings"], list)
        or len(evidence["bindings"]) > len(RUNTIME_BINDINGS)
        or not all(
            _runtime_binding_is_valid(binding)
            for binding in evidence["bindings"]
        )
        or not isinstance(evidence["management_endpoints"], list)
        or len(evidence["management_endpoints"]) > len(MANAGEMENT_ENDPOINTS)
        or not all(
            _management_endpoint_is_valid(endpoint)
            for endpoint in evidence["management_endpoints"]
        )
    ):
        return False
    try:
        checked = datetime.fromisoformat(
            evidence["checked_utc"].replace("Z", "+00:00")
        )
    except ValueError:
        return False
    if checked.tzinfo is None:
        return False
    result = evidence["result"]
    if result == "PASS":
        if evidence["blocker"] is not None or not evidence[
            "field_services_running"
        ]:
            return False
        services = evidence["services"]
        bindings = evidence["bindings"]
        endpoints = evidence["management_endpoints"]
        if (
            {service["name"] for service in services}
            != set(RUNTIME_SERVICES)
            or {binding["service"] for binding in bindings}
            != set(RUNTIME_BINDINGS)
            or {endpoint["service"] for endpoint in endpoints}
            != set(MANAGEMENT_ENDPOINTS)
        ):
            return False
        service_by_name = {
            service["name"]: service for service in services
        }
        if any(
            service["state"] != "RUNNING"
            or service["health"] != "HEALTHY"
            or service["restart_count"] != 0
            or service["oom_killed"]
            or not service["image_id_verified"]
            for service in service_by_name.values()
        ):
            return False
        binding_by_service = {
            binding["service"]: binding for binding in bindings
        }
        if any(
            (
                binding["container_port"],
                binding["host_port"],
                binding["scope"],
            )
            != expected
            or binding["result"] != "PASS"
            for name, expected in RUNTIME_BINDINGS.items()
            for binding in (binding_by_service[name],)
        ):
            return False
        endpoint_by_service = {
            endpoint["service"]: endpoint for endpoint in endpoints
        }
        return all(
            endpoint_by_service[name]
            == {
                "service": name,
                "port": port,
                "result": "READY",
            }
            for name, port in MANAGEMENT_ENDPOINTS.items()
        )
    return _safe_evidence_text(evidence["blocker"])


@dataclass(frozen=True)
class SshRuntimeVerification:
    transport: RuntimeRemoteTransportCapabilities
    workstation_ports: WorkstationPortCapabilities
    clock: Clock

    def _failed(
        self,
        configuration: TargetConfiguration,
        commit: str,
        run_id: str,
        outcome: str,
        blocker: str,
        remote: dict[str, object] | None = None,
        workstation_ports: list[dict[str, object]] | None = None,
    ) -> RuntimeVerification:
        try:
            cleanup_succeeded = self.transport.stop(
                configuration,
                commit,
                run_id,
            )
        except (OSError, subprocess.SubprocessError, TimeoutError):
            cleanup_succeeded = False
        if not cleanup_succeeded:
            outcome = "ERROR"
            blocker = (
                "Runtime verification failed and field-service cleanup "
                "could not be proven."
            )
        evidence: dict[str, object] = {
            "schema_version": HEALTH_AND_PORTS_SCHEMA_VERSION,
            "run_id": run_id,
            "target_alias": configuration.target_alias,
            "deployment_commit": commit,
            "checked_utc": _utc_text(self.clock.now()),
            "result": outcome,
            "services": remote["services"] if remote is not None else [],
            "bindings": remote["bindings"] if remote is not None else [],
            "management_endpoints": (
                remote["management_endpoints"]
                if remote is not None
                else []
            ),
            "workstation_ports": workstation_ports or [],
            "cleanup": {
                "attempted": True,
                "succeeded": cleanup_succeeded,
            },
        }
        return RuntimeVerification(
            passed=False,
            outcome=outcome,
            blocker=blocker,
            field_services_running=not cleanup_succeeded,
            evidence=evidence,
            observed_public_ports=(),
            observed_private_ports=(),
        )

    def verify(
        self,
        configuration: TargetConfiguration,
        commit: str,
        policy: dict[str, object],
        deployment_manifest: dict[str, object],
        run_id: str,
    ) -> RuntimeVerification:
        image_ids = deployment_manifest.get("service_image_ids")
        if not _image_ids_are_valid(image_ids, require_all=True):
            return self._failed(
                configuration,
                commit,
                run_id,
                "ERROR",
                "Deployment image evidence is unavailable for runtime verification.",
            )
        assert isinstance(image_ids, dict)
        try:
            execution = self.transport.inspect(
                configuration,
                commit,
                image_ids,
                run_id,
            )
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return self._failed(
                configuration,
                commit,
                run_id,
                "ERROR",
                "Remote runtime verification transport malfunctioned.",
            )
        if (
            execution.returncode != 0
            or len(execution.stdout) > 2 * 1024 * 1024
        ):
            return self._failed(
                configuration,
                commit,
                run_id,
                "ERROR",
                "Remote runtime verification transport malfunctioned.",
            )
        try:
            remote = json.loads(execution.stdout)
        except (UnicodeError, json.JSONDecodeError):
            return self._failed(
                configuration,
                commit,
                run_id,
                "ERROR",
                "Remote runtime verification evidence is malformed.",
            )
        if not _remote_runtime_evidence_is_valid(
            remote,
            configuration,
            commit,
            run_id,
        ):
            return self._failed(
                configuration,
                commit,
                run_id,
                "ERROR",
                "Remote runtime verification evidence is malformed.",
            )
        if remote["result"] != "PASS":
            return self._failed(
                configuration,
                commit,
                run_id,
                str(remote["result"]),
                str(remote["blocker"]),
                remote,
            )

        try:
            observations = self.workstation_ports.observe(
                configuration.vps_host,
                RUNTIME_PORTS,
            )
        except (OSError, TimeoutError):
            return self._failed(
                configuration,
                commit,
                run_id,
                "ERROR",
                "Workstation port observation malfunctioned.",
                remote,
            )
        if (
            not isinstance(observations, dict)
            or set(observations) != set(RUNTIME_PORTS)
            or not all(type(value) is bool for value in observations.values())
        ):
            return self._failed(
                configuration,
                commit,
                run_id,
                "ERROR",
                "Workstation port observation returned malformed evidence.",
                remote,
            )
        workstation_evidence = []
        for port in RUNTIME_PORTS:
            expected_reachable = port in PUBLIC_PORTS
            observed_reachable = observations[port]
            workstation_evidence.append(
                {
                    "port": port,
                    "expected": (
                        "REACHABLE"
                        if expected_reachable
                        else "UNREACHABLE"
                    ),
                    "observed": (
                        "REACHABLE"
                        if observed_reachable
                        else "UNREACHABLE"
                    ),
                    "result": (
                        "PASS"
                        if observed_reachable == expected_reachable
                        else "FAIL"
                    ),
                }
            )
        if any(
            observation["result"] != "PASS"
            for observation in workstation_evidence
        ):
            return self._failed(
                configuration,
                commit,
                run_id,
                "BLOCKED",
                (
                    "Workstation-observed protocol or management port "
                    "reachability violates the restricted validation posture."
                ),
                remote,
                workstation_evidence,
            )
        evidence = {
            "schema_version": HEALTH_AND_PORTS_SCHEMA_VERSION,
            "run_id": run_id,
            "target_alias": configuration.target_alias,
            "deployment_commit": commit,
            "checked_utc": _utc_text(self.clock.now()),
            "result": "PASS",
            "services": remote["services"],
            "bindings": remote["bindings"],
            "management_endpoints": remote["management_endpoints"],
            "workstation_ports": workstation_evidence,
            "cleanup": {
                "attempted": False,
                "succeeded": None,
            },
        }
        return RuntimeVerification(
            passed=True,
            outcome="PASS",
            blocker=None,
            field_services_running=True,
            evidence=evidence,
            observed_public_ports=PUBLIC_PORTS,
            observed_private_ports=PRIVATE_PORTS,
        )


@dataclass(frozen=True)
class ControllerAdapters:
    clock: Clock
    randomness: RandomSource
    repository: RepositoryCapabilities | None = None
    trusted_ci: TrustedCiCapabilities | None = None
    remote: RemoteCapabilities | None = None
    authorization: AuthorizationCapabilities | None = None
    deployment: DeploymentCapabilities | None = None
    runtime: RuntimeCapabilities | None = None


@dataclass(frozen=True)
class DeploymentRequest:
    check_only: bool
    commit: str | None
    env_file: Path | None
    output_dir: Path
    output_format: str = "human"
    verbose: bool = False
    cli_error: str | None = None

    @property
    def operation(self) -> str:
        return "ci_validation" if self.check_only else "vps_deployment"

    @property
    def target_state(self) -> str:
        return "CI_VALIDATED" if self.check_only else "ENVIRONMENT_VALIDATED"


@dataclass(frozen=True)
class TargetConfiguration:
    target_alias: str
    vps_host: str
    vps_user: str
    vps_ssh_port: int
    vps_ssh_key: Path
    vps_deploy_dir: str
    vps_project_name: str
    admin_source_cidr: str
    field_tarpit_cpu_limit: str
    field_tarpit_memory_limit: str | None


@dataclass(frozen=True)
class CheckResult:
    check_id: str
    phase: int
    status: str
    summary: str
    observed: str | None = None
    required: str | None = None
    next_action: str | None = None
    evidence: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        document: dict[str, object] = {
            "check_id": self.check_id,
            "phase": self.phase,
            "status": self.status,
            "summary": self.summary,
        }
        for name in ("observed", "required", "next_action"):
            value = getattr(self, name)
            if value is not None:
                document[name] = value
        if self.evidence:
            document["evidence"] = list(self.evidence)
        return document


@dataclass(frozen=True)
class DeploymentResult:
    schema_version: int
    run_id: str
    operation: str
    target_state: str | None
    highest_state: str | None
    outcome: str
    exit_code: int
    started_utc: str
    finished_utc: str
    remote_mutation_occurred: bool
    field_services_running: bool
    checks: tuple[CheckResult, ...] = field(default_factory=tuple)
    evidence: dict[str, str] = field(default_factory=dict)
    next_action: str = ""

    def to_dict(self) -> dict[str, object]:
        document = asdict(self)
        document["checks"] = [check.to_dict() for check in self.checks]
        return document


class EvidenceError(RuntimeError):
    """Raised when safe run-scoped evidence cannot be written."""

    def __init__(
        self,
        message: str,
        *,
        result: DeploymentResult | None = None,
    ) -> None:
        super().__init__(message)
        self.result = result


class ContractError(RuntimeError):
    """Raised when versioned deployment policy is unsupported or malformed."""


class TargetConfigurationError(RuntimeError):
    """Raised when strict operator target data violates the contract."""


class CliUsageError(RuntimeError):
    """Raised when command arguments violate the public CLI contract."""


class ContractArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        raise CliUsageError(message)


def _require_exact_keys(
    document: dict[str, object],
    expected: set[str],
    artifact_name: str,
) -> None:
    actual = set(document)
    if actual != expected:
        unknown = sorted(actual - expected)
        missing = sorted(expected - actual)
        detail = []
        if unknown:
            detail.append(f"unknown fields: {', '.join(unknown)}")
        if missing:
            detail.append(f"missing fields: {', '.join(missing)}")
        raise ContractError(f"{artifact_name} has " + "; ".join(detail))


def _load_policy() -> tuple[dict[str, object], str]:
    path = REPO_ROOT / "deploy/deployment-policy.json"
    try:
        content = path.read_bytes()
        policy = json.loads(content)
    except (OSError, json.JSONDecodeError) as error:
        raise ContractError("deployment policy cannot be read as JSON") from error
    if not isinstance(policy, dict):
        raise ContractError("deployment policy must be a JSON object")

    _require_exact_keys(
        policy,
        {
            "schema_version",
            "controller_contract_version",
            "trusted_repository",
            "trusted_remote",
            "approved_ref",
            "ci",
            "field_build",
            "protected_paths",
            "supported_compose_files",
            "result_schema_version",
            "evidence_index_schema_version",
            "ci_proof_schema_version",
            "remote_preflight_schema_version",
            "compose_config_schema_version",
            "deployment_manifest_schema_version",
            "health_and_ports_schema_version",
        },
        "deployment policy",
    )
    expected_constants = {
        "schema_version": 1,
        "controller_contract_version": CONTROLLER_CONTRACT_VERSION,
        "trusted_repository": "honeynet/EventHorizon",
        "trusted_remote": "upstream",
        "approved_ref": "refs/remotes/upstream/GSoC_2026",
        "result_schema_version": RESULT_SCHEMA_VERSION,
        "evidence_index_schema_version": EVIDENCE_INDEX_SCHEMA_VERSION,
        "ci_proof_schema_version": CI_PROOF_SCHEMA_VERSION,
        "remote_preflight_schema_version": REMOTE_PREFLIGHT_SCHEMA_VERSION,
        "compose_config_schema_version": COMPOSE_CONFIG_SCHEMA_VERSION,
        "deployment_manifest_schema_version": (
            DEPLOYMENT_MANIFEST_SCHEMA_VERSION
        ),
        "health_and_ports_schema_version": (
            HEALTH_AND_PORTS_SCHEMA_VERSION
        ),
    }
    for name, expected in expected_constants.items():
        if policy[name] != expected:
            raise ContractError(f"deployment policy has unsupported {name}")

    ci = policy["ci"]
    if not isinstance(ci, dict):
        raise ContractError("deployment policy ci field must be an object")
    _require_exact_keys(
        ci,
        {"workflow_path", "event", "head_branch", "required_jobs"},
        "deployment policy ci",
    )
    required_jobs = [
        "build-unit",
        "deployment-controller",
        "shell-quality",
        "configuration-policy",
        "container-builds",
        "deterministic-smoke",
        "ci-contract",
    ]
    if ci != {
        "workflow_path": ".github/workflows/ci.yml",
        "event": "push",
        "head_branch": "GSoC_2026",
        "required_jobs": required_jobs,
    }:
        raise ContractError("deployment policy has unsupported CI contract")

    field_build = policy["field_build"]
    if field_build != {
        "platform": "linux/amd64",
        "dockerfiles": [
            "docker/tarpits/Dockerfile",
            "docker/prometheus/Dockerfile",
        ],
        "base_images": [
            (
                "gcc:12.5.0-bookworm@sha256:"
                "01cfb27075399638ccdffa855970683ad298a3fad61012d7ab62523abbff5d20"
            ),
            (
                "golang:1.23.9-bookworm@sha256:"
                "0c9738aabadd34e99cf5263ae1337ad5330126c87a1fab4ffabec2284944c991"
            ),
            (
                "debian:bookworm-slim@sha256:"
                "63a496b5d3b99214b39f5ed70eb71a61e590a77979c79cbee4faf991f8c0783e"
            ),
        ],
        "compose_images": {
            "prometheus": (
                "prom/prometheus:v3.5.0@sha256:"
                "8672a850efe2f9874702406c8318704edb363587f8c2ca88586b4c8fdb5cea24"
            ),
            "grafana": (
                "grafana/grafana-oss:12.1.0@sha256:"
                "11c2e6c7993917ea89292b942e3428f73907b2809d554154bfb8b4ceb2301cc8"
            ),
            "cadvisor": (
                "ghcr.io/google/cadvisor:v0.57.0@sha256:"
                "1742bab953d9d9ab166cba24604a9488efdff7d73dc6d18a087c09a1bcd6cb9d"
            ),
        },
        "go_toolchain": "1.23.9",
        "go_module_mode": "readonly",
    }:
        raise ContractError("deployment policy has unsupported field build contract")

    protected_paths = policy["protected_paths"]
    compose_files = policy["supported_compose_files"]
    for name, values in (
        ("protected_paths", protected_paths),
        ("supported_compose_files", compose_files),
    ):
        if (
            not isinstance(values, list)
            or not values
            or not all(isinstance(value, str) and value for value in values)
            or len(set(values)) != len(values)
        ):
            raise ContractError(f"deployment policy {name} must be unique paths")
    if any(
        character in path
        for path in protected_paths
        for character in ("*", "?", "[", "]")
    ):
        raise ContractError("deployment policy protected paths must not use globs")

    return policy, hashlib.sha256(content).hexdigest()


def _load_target_configuration(
    path: Path,
    repository: RepositoryCapabilities,
) -> TargetConfiguration:
    try:
        details = path.lstat()
    except OSError as error:
        raise TargetConfigurationError(
            "Target configuration file is missing or unreadable."
        ) from error
    if stat.S_ISLNK(details.st_mode) or not stat.S_ISREG(details.st_mode):
        raise TargetConfigurationError(
            "Target configuration must be a regular file, not a symlink."
        )
    if details.st_uid != os.getuid():
        raise TargetConfigurationError(
            "Target configuration must be owned by the operator."
        )
    if stat.S_IMODE(details.st_mode) != 0o600:
        raise TargetConfigurationError(
            "Target configuration file mode must be exactly 0600."
        )
    if not repository.target_file_is_ignored(path):
        raise TargetConfigurationError(
            "Target configuration must be ignored by Git."
        )

    try:
        if details.st_size > 64 * 1024:
            raise TargetConfigurationError("Target configuration is too large.")
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        raise TargetConfigurationError(
            "Target configuration must be readable UTF-8 data."
        ) from error

    known_keys = {
        "TARGET_ALIAS",
        "VPS_HOST",
        "VPS_USER",
        "VPS_SSH_PORT",
        "VPS_SSH_KEY",
        "VPS_DEPLOY_DIR",
        "VPS_PROJECT_NAME",
        "ADMIN_SOURCE_CIDR",
        "FIELD_TARPIT_CPU_LIMIT",
        "FIELD_TARPIT_MEMORY_LIMIT",
    }
    values: dict[str, str] = {}
    forbidden_value_characters = set("$`\\'\";|&<>")
    for line_number, line in enumerate(lines, start=1):
        if not line or line.startswith("#"):
            continue
        if line != line.strip() or "=" not in line:
            raise TargetConfigurationError(
                f"Target configuration line {line_number} is not KEY=VALUE data."
            )
        key, value = line.split("=", 1)
        if key not in known_keys:
            raise TargetConfigurationError(
                f"Target configuration line {line_number} uses an unknown key."
            )
        if key in values:
            raise TargetConfigurationError(
                f"Target configuration contains duplicate key {key!r}."
            )
        if (
            any(
                character.isspace()
                or ord(character) < 0x20
                or ord(character) == 0x7F
                for character in value
            )
            or any(character in forbidden_value_characters for character in value)
        ):
            raise TargetConfigurationError(
                f"Target configuration value for {key} is not strict data."
            )
        values[key] = value

    missing = sorted(known_keys - set(values))
    if missing:
        raise TargetConfigurationError(
            "Target configuration is missing required keys: " + ", ".join(missing)
        )
    for key in known_keys - {"FIELD_TARPIT_MEMORY_LIMIT"}:
        if not values[key]:
            raise TargetConfigurationError(
                f"Target configuration value for {key} must not be empty."
            )

    target_alias = values["TARGET_ALIAS"]
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", target_alias):
        raise TargetConfigurationError("TARGET_ALIAS has an invalid format.")

    vps_host = values["VPS_HOST"]
    try:
        ipaddress.ip_address(vps_host)
    except ValueError:
        valid_hostname = (
            len(vps_host) <= 253
            and ".." not in vps_host
            and all(
                re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
                for label in vps_host.rstrip(".").split(".")
            )
        )
        if not valid_hostname:
            raise TargetConfigurationError("VPS_HOST has an invalid format.") from None

    vps_user = values["VPS_USER"]
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", vps_user):
        raise TargetConfigurationError("VPS_USER has an invalid format.")

    try:
        vps_ssh_port = int(values["VPS_SSH_PORT"], 10)
    except ValueError:
        raise TargetConfigurationError(
            "VPS_SSH_PORT must be an integer from 1 through 65535."
        ) from None
    if not 1 <= vps_ssh_port <= 65535:
        raise TargetConfigurationError(
            "VPS_SSH_PORT must be an integer from 1 through 65535."
        )

    vps_ssh_key = Path(values["VPS_SSH_KEY"])
    if not vps_ssh_key.is_absolute():
        raise TargetConfigurationError("VPS_SSH_KEY must be an absolute path.")
    try:
        key_details = vps_ssh_key.lstat()
    except OSError as error:
        raise TargetConfigurationError(
            "VPS_SSH_KEY must identify a readable regular file."
        ) from error
    if (
        stat.S_ISLNK(key_details.st_mode)
        or not stat.S_ISREG(key_details.st_mode)
        or not os.access(vps_ssh_key, os.R_OK)
        or stat.S_IMODE(key_details.st_mode) & 0o077
    ):
        raise TargetConfigurationError(
            "VPS_SSH_KEY must be a private operator-readable regular file."
        )
    try:
        vps_ssh_key.resolve().relative_to(REPO_ROOT.resolve())
    except ValueError:
        pass
    else:
        raise TargetConfigurationError(
            "VPS_SSH_KEY must not be stored inside the repository."
        )

    vps_deploy_dir = values["VPS_DEPLOY_DIR"]
    deploy_path = PurePosixPath(vps_deploy_dir)
    unsafe_roots = {
        "/",
        "/bin",
        "/boot",
        "/dev",
        "/etc",
        "/home",
        "/lib",
        "/lib64",
        "/proc",
        "/root",
        "/run",
        "/sbin",
        "/sys",
        "/tmp",
        "/usr",
        "/var",
    }
    if (
        not deploy_path.is_absolute()
        or ".." in deploy_path.parts
        or str(deploy_path) != vps_deploy_dir
        or vps_deploy_dir in unsafe_roots
        or len(deploy_path.parts) < 3
    ):
        raise TargetConfigurationError(
            "VPS_DEPLOY_DIR must be an absolute narrowly scoped path."
        )

    project_name = values["VPS_PROJECT_NAME"]
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,62}", project_name):
        raise TargetConfigurationError(
            "VPS_PROJECT_NAME has an invalid Compose project format."
        )

    try:
        ipaddress.ip_network(values["ADMIN_SOURCE_CIDR"], strict=False)
    except ValueError:
        raise TargetConfigurationError(
            "ADMIN_SOURCE_CIDR must be a valid IPv4 or IPv6 network."
        ) from None
    if "/" not in values["ADMIN_SOURCE_CIDR"]:
        raise TargetConfigurationError(
            "ADMIN_SOURCE_CIDR must include a prefix length."
        )

    try:
        cpu_limit = Decimal(values["FIELD_TARPIT_CPU_LIMIT"])
    except InvalidOperation:
        raise TargetConfigurationError(
            "FIELD_TARPIT_CPU_LIMIT must be a positive decimal."
        ) from None
    if not cpu_limit.is_finite() or not Decimal("0") < cpu_limit <= Decimal("64"):
        raise TargetConfigurationError(
            "FIELD_TARPIT_CPU_LIMIT must be a positive decimal no greater than 64."
        )

    memory_limit = values["FIELD_TARPIT_MEMORY_LIMIT"] or None
    if memory_limit is not None:
        match = re.fullmatch(r"([0-9]+)([bBkKmMgG]|[kKmMgG][bB])", memory_limit)
        if match is None or int(match.group(1), 10) < 1:
            raise TargetConfigurationError(
                "FIELD_TARPIT_MEMORY_LIMIT must use a positive Docker size unit."
            )

    return TargetConfiguration(
        target_alias=target_alias,
        vps_host=vps_host,
        vps_user=vps_user,
        vps_ssh_port=vps_ssh_port,
        vps_ssh_key=vps_ssh_key,
        vps_deploy_dir=vps_deploy_dir,
        vps_project_name=project_name,
        admin_source_cidr=values["ADMIN_SOURCE_CIDR"],
        field_tarpit_cpu_limit=values["FIELD_TARPIT_CPU_LIMIT"],
        field_tarpit_memory_limit=memory_limit,
    )


def _utc_text(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("clock returned a timezone-naive timestamp")
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _make_run_id(started: datetime, randomness: RandomSource) -> str:
    suffix = randomness.run_suffix()
    if not re.fullmatch(r"[a-z0-9]{6,32}", suffix):
        raise EvidenceError("random source returned an invalid run suffix")
    return f"deploy-{started.astimezone(timezone.utc):%Y%m%dT%H%M%SZ}-{suffix}"


def _assert_safe_existing_directory(path: Path) -> None:
    details = path.lstat()
    if stat.S_ISLNK(details.st_mode):
        raise EvidenceError("output directory must not be a symlink")
    if not stat.S_ISDIR(details.st_mode):
        raise EvidenceError("output directory must be a directory")
    if details.st_uid != os.getuid():
        raise EvidenceError("output directory must be owned by the operator")
    if stat.S_IMODE(details.st_mode) & 0o022:
        raise EvidenceError("output directory must not be group/world writable")


def _prepare_run_directory(output_base: Path, run_id: str) -> Path:
    output_base = output_base.absolute()
    if output_base.exists() or output_base.is_symlink():
        _assert_safe_existing_directory(output_base)
    else:
        parent = output_base.parent
        while not parent.exists() and not parent.is_symlink():
            parent = parent.parent
        _assert_safe_existing_directory(parent)
        output_base.mkdir(mode=0o700, parents=True, exist_ok=False)
        os.chmod(output_base, 0o700)

    deployments = output_base / "deployments"
    if deployments.exists() or deployments.is_symlink():
        _assert_safe_existing_directory(deployments)
    else:
        deployments.mkdir(mode=0o700)
        os.chmod(deployments, 0o700)

    run_directory = deployments / run_id
    try:
        run_directory.mkdir(mode=0o700)
    except FileExistsError as error:
        raise EvidenceError("run identifier collision") from error
    os.chmod(run_directory, 0o700)
    return run_directory


def _atomic_write(path: Path, content: bytes) -> None:
    descriptor = -1
    temporary_name = ""
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.",
            dir=path.parent,
        )
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as destination:
            descriptor = -1
            destination.write(content)
            destination.flush()
            os.fsync(destination.fileno())
        os.replace(temporary_name, path)
        temporary_name = ""
        os.chmod(path, 0o600)
    except OSError as error:
        raise EvidenceError(f"could not write {path.name}") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary_name:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass


def _json_bytes(document: object) -> bytes:
    return (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _summary(result: DeploymentResult, run_directory: Path) -> str:
    highest_state = result.highest_state or "NONE"
    return "\n".join(
        (
            "# EventHorizon deployment result",
            "",
            f"Outcome: **{result.outcome}**",
            f"Highest proven state: **{highest_state}**",
            "Remote mutation occurred: "
            + ("**yes**" if result.remote_mutation_occurred else "**no**"),
            "Field services remain running: "
            + ("**yes**" if result.field_services_running else "**no**"),
            f"Next action: {result.next_action}",
            f"Evidence path: `{run_directory}`",
            "",
        )
    )


def _artifact_entry(run_directory: Path, filename: str) -> dict[str, object]:
    path = run_directory / filename
    if path.is_file():
        content = path.read_bytes()
        return {
            "filename": filename,
            "size_bytes": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
            "collection_status": "COLLECTED",
            "reason": None,
        }
    return {
        "filename": filename,
        "size_bytes": None,
        "sha256": None,
        "collection_status": "NOT_APPLICABLE",
        "reason": "Run ended before this artifact applied.",
    }


def _write_evidence(
    result: DeploymentResult,
    run_directory: Path,
    generated_utc: str,
    json_artifacts: dict[str, dict[str, object]] | None = None,
) -> None:
    for filename, document in (json_artifacts or {}).items():
        if filename not in EXPECTED_EVIDENCE or not filename.endswith(".json"):
            raise EvidenceError("controller attempted to write an unallowlisted artifact")
        _atomic_write(run_directory / filename, _json_bytes(document))
    _atomic_write(run_directory / "result.json", _json_bytes(result.to_dict()))
    _atomic_write(
        run_directory / "summary.md",
        _summary(result, run_directory).encode("utf-8"),
    )
    index = {
        "schema_version": EVIDENCE_INDEX_SCHEMA_VERSION,
        "run_id": result.run_id,
        "generated_utc": generated_utc,
        "artifacts": [
            _artifact_entry(run_directory, filename)
            for filename in EXPECTED_EVIDENCE
        ],
    }
    _atomic_write(run_directory / "evidence-index.json", _json_bytes(index))


def run(
    request: DeploymentRequest,
    adapters: ControllerAdapters,
) -> DeploymentResult:
    started = adapters.clock.now()
    run_id = _make_run_id(started, adapters.randomness)
    run_directory = _prepare_run_directory(request.output_dir, run_id)

    checks: list[CheckResult] = []
    json_artifacts: dict[str, dict[str, object]] = {}
    highest_state: str | None = None
    outcome = "BLOCKED"
    exit_code_override: int | None = None
    remote_mutation_occurred = False
    field_services_running = False
    policy: dict[str, object] | None = None
    policy_sha256: str | None = None

    try:
        policy, policy_sha256 = _load_policy()
        checks.append(
            CheckResult(
                check_id="deployment_policy",
                phase=1,
                status="PASS",
                summary="Deployment policy and contract version are supported.",
            )
        )
    except ContractError as error:
        next_action = "Restore a supported versioned deployment policy."
        checks.append(
            CheckResult(
                check_id="deployment_policy",
                phase=1,
                status="BLOCKER",
                summary="Deployment policy is unsupported or malformed.",
                observed=str(error),
                next_action=next_action,
            )
        )

    if policy is None:
        pass
    elif request.cli_error is not None:
        next_action = "Correct the documented command arguments and retry."
        checks.append(
            CheckResult(
                check_id="cli_arguments",
                phase=1,
                status="BLOCKER",
                summary="Command arguments are invalid.",
                next_action=next_action,
            )
        )
    elif request.commit is None or not FULL_SHA_PATTERN.fullmatch(request.commit):
        next_action = "Provide a full 40-character deployment commit SHA."
        checks.append(
            CheckResult(
                check_id="deployment_commit",
                phase=1,
                status="BLOCKER",
                summary="Deployment commit is not a full SHA.",
                observed="Missing or invalid commit identifier.",
                required="Exactly 40 hexadecimal characters.",
                next_action=next_action,
            )
        )
    elif request.check_only and request.env_file is not None:
        next_action = "Remove --env-file from the check-only invocation."
        checks.append(
            CheckResult(
                check_id="check_only_arguments",
                phase=1,
                status="BLOCKER",
                summary="Check-only does not load target configuration.",
                next_action=next_action,
            )
        )
    elif not request.check_only and request.env_file is None:
        next_action = "Provide the strict ignored target file with --env-file."
        checks.append(
            CheckResult(
                check_id="target_configuration_argument",
                phase=1,
                status="BLOCKER",
                summary="Deployment requires a target configuration file.",
                next_action=next_action,
            )
        )
    elif adapters.repository is None:
        next_action = "Configure the local repository verification capability."
        checks.append(
            CheckResult(
                check_id="deployment_candidate",
                phase=2,
                status="BLOCKER",
                summary="Deployment-candidate verification is unavailable.",
                next_action=next_action,
            )
        )
    else:
        commit = request.commit.lower()
        candidate = adapters.repository.verify_candidate(commit, policy)
        for warning in candidate.warnings:
            checks.append(
                CheckResult(
                    check_id="repository_warning",
                    phase=2,
                    status="WARNING",
                    summary=warning,
                )
            )
        if not candidate.passed:
            next_action = candidate.blocker or (
                "Resolve deployment-candidate and protected-path blockers."
            )
            checks.append(
                CheckResult(
                    check_id="deployment_candidate",
                    phase=2,
                    status="BLOCKER",
                    summary="Deployment candidate or controller is incompatible.",
                    next_action=next_action,
                )
            )
        else:
            highest_state = "DEPLOYMENT_CANDIDATE"
            checks.append(
                CheckResult(
                    check_id="deployment_candidate",
                    phase=2,
                    status="PASS",
                    summary="Deployment candidate and protected paths are compatible.",
                )
            )
            json_artifacts["controller-manifest.json"] = {
                "schema_version": 1,
                "controller_contract_version": CONTROLLER_CONTRACT_VERSION,
                "deployment_commit": commit,
                "policy_sha256": policy_sha256,
                "protected_path_sha256": candidate.protected_hashes,
            }

            if adapters.trusted_ci is None:
                next_action = (
                    "Provide trusted-upstream push-workflow proof for the exact commit."
                )
                checks.append(
                    CheckResult(
                        check_id="trusted_ci",
                        phase=2,
                        status="BLOCKER",
                        summary="Trusted CI verification is unavailable.",
                        next_action=next_action,
                    )
                )
            else:
                ci = adapters.trusted_ci.verify(commit, policy)
                if not ci.passed:
                    if ci.outcome in {"ERROR", "INCONCLUSIVE"}:
                        outcome = ci.outcome
                    check_status = {
                        "ERROR": "ERROR",
                        "INCONCLUSIVE": "INCONCLUSIVE",
                    }.get(ci.outcome, "BLOCKER")
                    next_action = ci.blocker or (
                        "Resolve the trusted-upstream CI proof blocker."
                    )
                    checks.append(
                        CheckResult(
                            check_id="trusted_ci",
                            phase=2,
                            status=check_status,
                            summary="Exact-commit trusted CI proof is unavailable.",
                            next_action=next_action,
                        )
                    )
                else:
                    highest_state = "CI_VALIDATED"
                    checks.append(
                        CheckResult(
                            check_id="trusted_ci",
                            phase=2,
                            status="PASS",
                            summary="Exact deployment commit is CI_VALIDATED.",
                        )
                    )
                    json_artifacts["ci-proof.json"] = ci.proof
                    if request.check_only:
                        outcome = "PASS"
                        next_action = (
                            "Use the deployment command with the same exact commit "
                            "and a strict target configuration."
                        )
                    else:
                        target_file = request.env_file
                        assert target_file is not None
                        try:
                            target_configuration = _load_target_configuration(
                                target_file,
                                adapters.repository,
                            )
                        except TargetConfigurationError as error:
                            next_action = (
                                "Correct the strict ignored target configuration."
                            )
                            checks.append(
                                CheckResult(
                                    check_id="target_configuration",
                                    phase=3,
                                    status="BLOCKER",
                                    summary="Target configuration is invalid.",
                                    observed=str(error),
                                    next_action=next_action,
                                )
                            )
                        else:
                            checks.append(
                                CheckResult(
                                    check_id="target_configuration",
                                    phase=3,
                                    status="PASS",
                                    summary=(
                                        "Strict ignored target configuration "
                                        "satisfies local policy."
                                    ),
                                )
                            )
                            if adapters.remote is None:
                                next_action = (
                                    "Implement the non-mutating remote preflight "
                                    "capability."
                                )
                                checks.append(
                                    CheckResult(
                                        check_id="remote_preflight_foundation",
                                        phase=4,
                                        status="BLOCKER",
                                        summary=(
                                            "Remote preflight is intentionally "
                                            "unavailable in this foundation slice."
                                        ),
                                        next_action=next_action,
                                    )
                                )
                            else:
                                remote_preflight = adapters.remote.preflight(
                                    target_configuration,
                                    commit,
                                    policy,
                                )
                                if not remote_preflight.passed:
                                    if remote_preflight.outcome in {
                                        "ERROR",
                                        "INCONCLUSIVE",
                                    }:
                                        outcome = remote_preflight.outcome
                                    next_action = remote_preflight.blocker or (
                                        "Resolve the remote preflight blocker."
                                    )
                                    remote_status = {
                                        "ERROR": "ERROR",
                                        "INCONCLUSIVE": "INCONCLUSIVE",
                                    }.get(
                                        remote_preflight.outcome,
                                        "BLOCKER",
                                    )
                                    remote_summary = {
                                        "ERROR": (
                                            "Remote preflight tooling or "
                                            "infrastructure malfunctioned."
                                        ),
                                        "INCONCLUSIVE": (
                                            "Remote preflight evidence is "
                                            "insufficient."
                                        ),
                                    }.get(
                                        remote_preflight.outcome,
                                        "Remote preflight is blocked.",
                                    )
                                    checks.append(
                                        CheckResult(
                                            check_id="remote_preflight",
                                            phase=4,
                                            status=remote_status,
                                            summary=remote_summary,
                                            next_action=next_action,
                                        )
                                    )
                                    if remote_preflight.evidence:
                                        json_artifacts[
                                            "remote-preflight.json"
                                        ] = remote_preflight.evidence
                                else:
                                    checks.append(
                                        CheckResult(
                                            check_id="remote_preflight",
                                            phase=4,
                                            status="PASS",
                                            summary=(
                                                "Non-mutating remote preflight "
                                                "satisfies policy."
                                            ),
                                        )
                                    )
                                    json_artifacts["remote-preflight.json"] = (
                                        remote_preflight.evidence
                                    )
                                    if adapters.authorization is None:
                                        next_action = (
                                            "Run deployment from an interactive "
                                            "TTY with authorization capability."
                                        )
                                        checks.append(
                                            CheckResult(
                                                check_id="authorization",
                                                phase=5,
                                                status="BLOCKER",
                                                summary=(
                                                    "Interactive authorization is "
                                                    "unavailable."
                                                ),
                                                next_action=next_action,
                                            )
                                        )
                                    else:
                                        phrase = (
                                            f"AUTHORIZE DEPLOY {commit} TO "
                                            f"{target_configuration.target_alias}"
                                        )
                                        authorization_interrupted = False
                                        try:
                                            authorization = (
                                                adapters.authorization.authorize(
                                                    phrase
                                                )
                                            )
                                        except KeyboardInterrupt:
                                            authorization = AuthorizationDecision(
                                                authorized=False
                                            )
                                            authorization_interrupted = True
                                        authorization_time = _utc_text(
                                            adapters.clock.now()
                                        )
                                        authorization_evidence = {
                                            "authorization_attested": (
                                                authorization.authorized
                                            ),
                                            "firewall_policy_reviewed": (
                                                authorization.authorized
                                            ),
                                            "admin_source_restriction_attested": (
                                                authorization.authorized
                                            ),
                                            "attestation_utc": authorization_time,
                                            "deployment_commit": commit,
                                            "target_alias": (
                                                target_configuration.target_alias
                                            ),
                                            "observed_public_ports": [],
                                            "observed_private_ports": [],
                                            "result": (
                                                "PASS"
                                                if authorization.authorized
                                                else "CANCELLED"
                                            ),
                                        }
                                        json_artifacts["authorization.json"] = (
                                            authorization_evidence
                                        )
                                        if not authorization.authorized:
                                            outcome = "CANCELLED"
                                            if authorization_interrupted:
                                                exit_code_override = 130
                                            next_action = (
                                                "Rerun when ready to authorize the "
                                                "exact commit and target alias."
                                            )
                                            checks.append(
                                                CheckResult(
                                                    check_id="authorization",
                                                    phase=5,
                                                    status="WARNING",
                                                    summary=(
                                                        "Authorization was "
                                                        + (
                                                            "interrupted."
                                                            if authorization_interrupted
                                                            else (
                                                                "declined by the "
                                                                "operator."
                                                            )
                                                        )
                                                    ),
                                                )
                                            )
                                        else:
                                            checks.append(
                                                CheckResult(
                                                    check_id="authorization",
                                                    phase=5,
                                                    status="PASS",
                                                    summary=(
                                                        "Operator authorized the "
                                                        "exact commit and target."
                                                    ),
                                                )
                                            )
                                            if adapters.deployment is None:
                                                next_action = (
                                                    "Implement exact-source remote "
                                                    "deployment."
                                                )
                                                checks.append(
                                                    CheckResult(
                                                        check_id=(
                                                            "exact_source_deployment_"
                                                            "foundation"
                                                        ),
                                                        phase=6,
                                                        status="BLOCKER",
                                                        summary=(
                                                            "Remote mutation remains "
                                                            "unimplemented."
                                                        ),
                                                        next_action=next_action,
                                                    )
                                                )
                                            else:
                                                deployment = (
                                                    adapters.deployment.deploy(
                                                        target_configuration,
                                                        commit,
                                                        policy,
                                                        remote_preflight.evidence,
                                                        run_id,
                                                    )
                                                )
                                                remote_mutation_occurred = (
                                                    deployment
                                                    .remote_mutation_occurred
                                                )
                                                field_services_running = (
                                                    deployment
                                                    .field_services_running
                                                )
                                                if deployment.compose_config:
                                                    json_artifacts[
                                                        "compose-config.json"
                                                    ] = deployment.compose_config
                                                if deployment.deployment_manifest:
                                                    json_artifacts[
                                                        "deployment-manifest.json"
                                                    ] = (
                                                        deployment
                                                        .deployment_manifest
                                                    )
                                                if deployment.passed:
                                                    checks.append(
                                                        CheckResult(
                                                            check_id=(
                                                                "exact_source_"
                                                                "deployment"
                                                            ),
                                                            phase=6,
                                                            status="PASS",
                                                            summary=(
                                                                "Exact source was "
                                                                "deployed on the "
                                                                "authorized VPS."
                                                            ),
                                                        )
                                                    )
                                                    if adapters.runtime is None:
                                                        next_action = (
                                                            "Implement runtime "
                                                            "health and private/"
                                                            "public port "
                                                            "verification."
                                                        )
                                                        checks.append(
                                                            CheckResult(
                                                                check_id=(
                                                                    "runtime_"
                                                                    "verification_"
                                                                    "foundation"
                                                                ),
                                                                phase=7,
                                                                status="BLOCKER",
                                                                summary=(
                                                                    "Runtime "
                                                                    "verification "
                                                                    "remains "
                                                                    "unimplemented."
                                                                ),
                                                                next_action=(
                                                                    next_action
                                                                ),
                                                            )
                                                        )
                                                    else:
                                                        runtime = (
                                                            adapters.runtime.verify(
                                                                target_configuration,
                                                                commit,
                                                                policy,
                                                                (
                                                                    deployment
                                                                    .deployment_manifest
                                                                ),
                                                                run_id,
                                                            )
                                                        )
                                                        field_services_running = (
                                                            runtime
                                                            .field_services_running
                                                        )
                                                        if runtime.evidence:
                                                            json_artifacts[
                                                                "health-and-ports.json"
                                                            ] = runtime.evidence
                                                        if runtime.passed:
                                                            authorization_evidence[
                                                                "observed_public_ports"
                                                            ] = list(
                                                                runtime
                                                                .observed_public_ports
                                                            )
                                                            authorization_evidence[
                                                                "observed_private_ports"
                                                            ] = list(
                                                                runtime
                                                                .observed_private_ports
                                                            )
                                                            checks.append(
                                                                CheckResult(
                                                                    check_id=(
                                                                        "runtime_"
                                                                        "verification"
                                                                    ),
                                                                    phase=7,
                                                                    status="PASS",
                                                                    summary=(
                                                                        "Runtime "
                                                                        "health, "
                                                                        "bindings, "
                                                                        "and port "
                                                                        "reachability "
                                                                        "passed."
                                                                    ),
                                                                )
                                                            )
                                                            next_action = (
                                                                "Implement the "
                                                                "deterministic "
                                                                "Telnet and MQTT "
                                                                "deployment smoke."
                                                            )
                                                            checks.append(
                                                                CheckResult(
                                                                    check_id=(
                                                                        "deployment_"
                                                                        "smoke_"
                                                                        "foundation"
                                                                    ),
                                                                    phase=8,
                                                                    status=(
                                                                        "BLOCKER"
                                                                    ),
                                                                    summary=(
                                                                        "Deterministic "
                                                                        "deployment "
                                                                        "smoke remains "
                                                                        "unimplemented."
                                                                    ),
                                                                    next_action=(
                                                                        next_action
                                                                    ),
                                                                )
                                                            )
                                                        else:
                                                            if runtime.outcome in {
                                                                "FAIL",
                                                                "ERROR",
                                                                "INCONCLUSIVE",
                                                            }:
                                                                outcome = (
                                                                    runtime.outcome
                                                                )
                                                            next_action = (
                                                                runtime.blocker
                                                                or (
                                                                    "Resolve the "
                                                                    "runtime "
                                                                    "verification "
                                                                    "blocker."
                                                                )
                                                            )
                                                            runtime_status = {
                                                                "FAIL": "FAIL",
                                                                "ERROR": "ERROR",
                                                                "INCONCLUSIVE": (
                                                                    "INCONCLUSIVE"
                                                                ),
                                                            }.get(
                                                                runtime.outcome,
                                                                "BLOCKER",
                                                            )
                                                            checks.append(
                                                                CheckResult(
                                                                    check_id=(
                                                                        "runtime_"
                                                                        "verification"
                                                                    ),
                                                                    phase=7,
                                                                    status=(
                                                                        runtime_status
                                                                    ),
                                                                    summary=(
                                                                        "Runtime "
                                                                        "verification "
                                                                        "did not pass."
                                                                    ),
                                                                    next_action=(
                                                                        next_action
                                                                    ),
                                                                )
                                                            )
                                                else:
                                                    if deployment.outcome in {
                                                        "FAIL",
                                                        "ERROR",
                                                        "INCONCLUSIVE",
                                                    }:
                                                        outcome = (
                                                            deployment.outcome
                                                        )
                                                    next_action = (
                                                        deployment.blocker
                                                        or (
                                                            "Inspect redacted "
                                                            "deployment evidence "
                                                            "and retry."
                                                        )
                                                    )
                                                    deployment_status = {
                                                        "FAIL": "FAIL",
                                                        "ERROR": "ERROR",
                                                        "INCONCLUSIVE": (
                                                            "INCONCLUSIVE"
                                                        ),
                                                    }.get(
                                                        deployment.outcome,
                                                        "BLOCKER",
                                                    )
                                                    checks.append(
                                                        CheckResult(
                                                            check_id=(
                                                                "exact_source_"
                                                                "deployment"
                                                            ),
                                                            phase=6,
                                                            status=(
                                                                deployment_status
                                                            ),
                                                            summary=(
                                                                "Exact-source "
                                                                "deployment did "
                                                                "not pass."
                                                            ),
                                                            next_action=next_action,
                                                        )
                                                    )

    finished = adapters.clock.now()
    evidence = {
        "result": "result.json",
        "summary": "summary.md",
        "evidence_index": "evidence-index.json",
    }
    if "controller-manifest.json" in json_artifacts:
        evidence["controller_manifest"] = "controller-manifest.json"
    if "ci-proof.json" in json_artifacts:
        evidence["ci_proof"] = "ci-proof.json"
    if "remote-preflight.json" in json_artifacts:
        evidence["remote_preflight"] = "remote-preflight.json"
    if "authorization.json" in json_artifacts:
        evidence["authorization"] = "authorization.json"
    if "compose-config.json" in json_artifacts:
        evidence["compose_config"] = "compose-config.json"
    if "deployment-manifest.json" in json_artifacts:
        evidence["deployment_manifest"] = "deployment-manifest.json"
    if "health-and-ports.json" in json_artifacts:
        evidence["health_and_ports"] = "health-and-ports.json"
    result = DeploymentResult(
        schema_version=RESULT_SCHEMA_VERSION,
        run_id=run_id,
        operation=request.operation,
        target_state=request.target_state,
        highest_state=highest_state,
        outcome=outcome,
        exit_code=exit_code_override or EXIT_CODES[outcome],
        started_utc=_utc_text(started),
        finished_utc=_utc_text(finished),
        remote_mutation_occurred=remote_mutation_occurred,
        field_services_running=field_services_running,
        checks=tuple(checks),
        evidence=evidence,
        next_action=next_action,
    )
    try:
        _write_evidence(
            result,
            run_directory,
            _utc_text(finished),
            json_artifacts=json_artifacts,
        )
    except EvidenceError as error:
        error.result = result
        raise
    return result


def build_argument_parser() -> argparse.ArgumentParser:
    parser = ContractArgumentParser(
        prog="vps_field_deploy.sh",
        add_help=False,
        usage=(
            "%(prog)s --check-only --commit <full-sha> [options]\n"
            "       %(prog)s --commit <full-sha> --env-file <path> [options]"
        ),
        description=(
            "Validate or deploy one exact trusted EventHorizon commit. "
            "Deployment remains fail-closed until every required phase is proven."
        ),
        epilog=(
            "After non-mutating preflight, deployment requires an interactive "
            "TTY and the exact phrase:\n"
            "  AUTHORIZE DEPLOY <full-SHA> TO <target-alias>\n"
            "Redirected input cannot authorize deployment."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-h",
        "--help",
        action="help",
        help="show this help without reading configuration or contacting a network",
    )
    parser.add_argument(
        "--check-only",
        action="store_true",
        help="target CI_VALIDATED without loading VPS configuration",
    )
    parser.add_argument("--commit", metavar="FULL_SHA", help="exact 40-character SHA")
    parser.add_argument(
        "--env-file",
        type=Path,
        metavar="PATH",
        help="strict ignored target configuration for a deployment",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("validation-output"),
        metavar="PATH",
        help="base directory under which deployments/<run-id> is created",
    )
    parser.add_argument(
        "--format",
        choices=("human", "json"),
        default="human",
        help="console output format (default: human)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="show additional redacted diagnostics",
    )
    return parser


def _best_effort_argument(
    arguments: Sequence[str],
    option: str,
) -> str | None:
    prefix = option + "="
    for index, argument in enumerate(arguments):
        if argument.startswith(prefix):
            return argument[len(prefix) :]
        if argument == option and index + 1 < len(arguments):
            following = arguments[index + 1]
            if not following.startswith("--"):
                return following
    return None


def production_adapters(
    *,
    authorization_input: TextIO | None = None,
    prompt_output: TextIO | None = None,
) -> ControllerAdapters:
    if authorization_input is None:
        authorization_input = sys.stdin
    if prompt_output is None:
        prompt_output = sys.stderr
    authorization = (
        InteractiveTtyAuthorization(
            authorization_input=authorization_input,
            prompt_output=prompt_output,
        )
        if authorization_input.isatty() and prompt_output.isatty()
        else None
    )
    return ControllerAdapters(
        clock=SystemClock(),
        randomness=SystemRandomSource(),
        repository=LocalGitRepository(REPO_ROOT),
        trusted_ci=TrustedGitHubActions(GitHubCliActionsApi()),
        remote=SshRemotePreflight(
            SystemSshProbeTransport(
                probe_path=REPO_ROOT / "scripts/vps_field_remote_probe.py",
            )
        ),
        authorization=authorization,
        deployment=SshExactSourceDeployment(
            SystemSshDeploymentTransport(
                deployment_program_path=(
                    REPO_ROOT / "scripts/vps_field_remote_deploy.py"
                ),
            )
        ),
        runtime=SshRuntimeVerification(
            transport=SystemSshRuntimeTransport(
                runtime_program_path=(
                    REPO_ROOT / "scripts/vps_field_remote_runtime.py"
                ),
            ),
            workstation_ports=SystemTcpPortProbe(),
            clock=SystemClock(),
        ),
    )


def main(arguments: Sequence[str] | None = None) -> int:
    raw_arguments = list(sys.argv[1:] if arguments is None else arguments)
    try:
        parsed = build_argument_parser().parse_args(raw_arguments)
        request = DeploymentRequest(
            check_only=parsed.check_only,
            commit=parsed.commit,
            env_file=parsed.env_file,
            output_dir=parsed.output_dir,
            output_format=parsed.format,
            verbose=parsed.verbose,
        )
    except CliUsageError as error:
        output_value = _best_effort_argument(raw_arguments, "--output-dir")
        format_value = _best_effort_argument(raw_arguments, "--format")
        commit_value = _best_effort_argument(raw_arguments, "--commit")
        env_value = _best_effort_argument(raw_arguments, "--env-file")
        request = DeploymentRequest(
            check_only="--check-only" in raw_arguments,
            commit=commit_value,
            env_file=Path(env_value) if env_value else None,
            output_dir=Path(output_value) if output_value else Path("validation-output"),
            output_format="json" if format_value == "json" else "human",
            verbose="--verbose" in raw_arguments,
            cli_error=str(error),
        )
    try:
        result = run(
            request,
            production_adapters(),
        )
    except EvidenceError as error:
        failed_result = error.result
        fallback = {
            "schema_version": RESULT_SCHEMA_VERSION,
            "operation": request.operation,
            "target_state": request.target_state,
            "highest_state": (
                failed_result.highest_state
                if failed_result is not None
                else None
            ),
            "outcome": "ERROR",
            "exit_code": EXIT_CODES["ERROR"],
            "remote_mutation_occurred": (
                failed_result.remote_mutation_occurred
                if failed_result is not None
                else False
            ),
            "field_services_running": (
                failed_result.field_services_running
                if failed_result is not None
                else False
            ),
            "next_action": (
                (
                    "Inspect the authorized field services, then choose a safe "
                    "writable evidence output directory."
                )
                if failed_result is not None
                and failed_result.remote_mutation_occurred
                else "Choose a safe writable evidence output directory."
            ),
        }
        if failed_result is not None:
            fallback["run_id"] = failed_result.run_id
        print(json.dumps(fallback, sort_keys=True), file=sys.stderr)
        return EXIT_CODES["ERROR"]
    document = result.to_dict()
    if request.output_format == "json":
        print(json.dumps(document, sort_keys=True))
    else:
        run_directory = request.output_dir.absolute() / "deployments" / result.run_id
        print(_summary(result, run_directory), end="")
    return result.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
