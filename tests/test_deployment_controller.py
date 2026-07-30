import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator, ValidationError

from scripts.deployment_controller import (
    AuthorizationDecision,
    CandidateVerification,
    CiVerification,
    ControllerAdapters,
    DeploymentRequest,
    DeploymentResult,
    EvidenceError,
    GitHubApiError,
    LocalGitRepository,
    RemotePreflightVerification,
    TrustedGitHubActions,
    run,
)


REPO_ROOT = Path(__file__).resolve().parents[1]


class DeploymentContractArtifactTests(unittest.TestCase):
    def test_versioned_policy_conforms_to_schema(self) -> None:
        policy = json.loads(
            (REPO_ROOT / "deploy/deployment-policy.json").read_text(encoding="utf-8")
        )
        schema = json.loads(
            (
                REPO_ROOT / "deploy/schemas/deployment-policy.schema.json"
            ).read_text(encoding="utf-8")
        )

        Draft202012Validator(schema).validate(policy)
        self.assertEqual(policy["schema_version"], 1)
        self.assertEqual(policy["controller_contract_version"], 1)
        self.assertEqual(
            policy["trusted_repository"], "honeynet/EventHorizon"
        )
        self.assertEqual(policy["trusted_remote"], "upstream")
        self.assertEqual(
            policy["approved_ref"],
            "refs/remotes/upstream/GSoC_2026",
        )
        self.assertEqual(
            policy["ci"]["required_jobs"],
            [
                "build-unit",
                "deployment-controller",
                "shell-quality",
                "configuration-policy",
                "container-builds",
                "deterministic-smoke",
                "ci-contract",
            ],
        )
        self.assertIn("scripts/vps_field_deploy.sh", policy["protected_paths"])
        self.assertIn("scripts/deployment_controller.py", policy["protected_paths"])
        self.assertIn(".github/workflows/ci.yml", policy["protected_paths"])

    def test_result_schema_accepts_partial_failure_and_rejects_drift(self) -> None:
        schema = json.loads(
            (
                REPO_ROOT / "deploy/schemas/deployment-result.schema.json"
            ).read_text(encoding="utf-8")
        )
        validator = Draft202012Validator(schema)
        partial_result = {
            "schema_version": 1,
            "run_id": "deploy-20260730T010203Z-a1b2c3",
            "operation": "ci_validation",
            "target_state": "CI_VALIDATED",
            "highest_state": None,
            "outcome": "BLOCKED",
            "exit_code": 2,
            "started_utc": "2026-07-30T01:02:03Z",
            "finished_utc": "2026-07-30T01:02:04Z",
            "remote_mutation_occurred": False,
            "field_services_running": False,
            "checks": [],
            "evidence": {},
            "next_action": "Provide a full deployment commit SHA.",
        }

        validator.validate(partial_result)

        unknown = dict(partial_result, unexpected=True)
        with self.assertRaises(ValidationError):
            validator.validate(unknown)

        unsupported = dict(partial_result, schema_version=2)
        with self.assertRaises(ValidationError):
            validator.validate(unsupported)

        for outcome, exit_codes in {
            "PASS": (0,),
            "BLOCKED": (2,),
            "FAIL": (3,),
            "INCONCLUSIVE": (4,),
            "ERROR": (5,),
            "CANCELLED": (6, 130),
        }.items():
            for exit_code in exit_codes:
                highest_state = (
                    "CI_VALIDATED" if outcome == "PASS" else None
                )
                validator.validate(
                    dict(
                        partial_result,
                        outcome=outcome,
                        exit_code=exit_code,
                        highest_state=highest_state,
                    )
                )

        with self.assertRaises(ValidationError):
            validator.validate(
                dict(partial_result, outcome="BLOCKED", exit_code=3)
            )
        with self.assertRaises(ValidationError):
            validator.validate(
                dict(
                    partial_result,
                    target_state="ENVIRONMENT_VALIDATED",
                )
            )
        with self.assertRaises(ValidationError):
            validator.validate(
                dict(
                    partial_result,
                    outcome="PASS",
                    exit_code=0,
                    highest_state=None,
                )
            )

    def test_evidence_index_schema_accepts_partial_collection(self) -> None:
        schema = json.loads(
            (
                REPO_ROOT / "deploy/schemas/evidence-index.schema.json"
            ).read_text(encoding="utf-8")
        )
        validator = Draft202012Validator(schema)
        index = {
            "schema_version": 1,
            "run_id": "deploy-20260730T010203Z-a1b2c3",
            "generated_utc": "2026-07-30T01:02:04Z",
            "artifacts": [
                {
                    "filename": "result.json",
                    "size_bytes": 123,
                    "sha256": "a" * 64,
                    "collection_status": "COLLECTED",
                    "reason": None,
                },
                {
                    "filename": "ci-proof.json",
                    "size_bytes": None,
                    "sha256": None,
                    "collection_status": "NOT_APPLICABLE",
                    "reason": "Run was blocked during preparation.",
                },
            ],
        }

        validator.validate(index)

        unknown = dict(index, unexpected=True)
        with self.assertRaises(ValidationError):
            validator.validate(unknown)

        unsupported = dict(index, schema_version=2)
        with self.assertRaises(ValidationError):
            validator.validate(unsupported)

    def test_ci_proof_schema_is_strict_and_attempt_specific(self) -> None:
        schema = json.loads(
            (
                REPO_ROOT / "deploy/schemas/ci-proof.schema.json"
            ).read_text(encoding="utf-8")
        )
        proof = successful_ci_proof("1" * 40, run_attempt=3)
        validator = Draft202012Validator(
            schema,
            format_checker=Draft202012Validator.FORMAT_CHECKER,
        )

        validator.validate(proof)
        with self.assertRaises(ValidationError):
            validator.validate(dict(proof, unexpected=True))
        with self.assertRaises(ValidationError):
            validator.validate(dict(proof, schema_version=2))
        with self.assertRaises(ValidationError):
            validator.validate(
                dict(
                    proof,
                    jobs=[
                        dict(proof["jobs"][0], conclusion="skipped"),
                        *proof["jobs"][1:],
                    ],
                )
            )

    def test_target_configuration_example_contains_only_strict_keys(self) -> None:
        entries = {}
        for line in (
            REPO_ROOT / "deploy/vps-field.env.example"
        ).read_text(encoding="utf-8").splitlines():
            if not line or line.startswith("#"):
                continue
            key, value = line.split("=", 1)
            self.assertNotIn(key, entries)
            entries[key] = value

        self.assertEqual(
            set(entries),
            {
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
            },
        )
        self.assertNotIn("DEPLOY_COMMIT", entries)
        self.assertNotIn("REPOSITORY_URL", entries)
        self.assertNotIn("PUBLIC_OBSERVATION_ALLOWED", entries)

    def test_ci_workflow_has_the_exact_stable_read_only_job_contract(self) -> None:
        workflow_path = REPO_ROOT / ".github/workflows/ci.yml"
        workflow_text = workflow_path.read_text(encoding="utf-8")
        workflow = yaml.safe_load(workflow_text)
        required_jobs = {
            "build-unit",
            "deployment-controller",
            "shell-quality",
            "configuration-policy",
            "container-builds",
            "deterministic-smoke",
            "ci-contract",
        }
        preceding_jobs = required_jobs - {"ci-contract"}

        self.assertEqual(workflow["permissions"], {"contents": "read"})
        self.assertEqual(set(workflow["jobs"]), required_jobs)
        self.assertEqual(
            workflow["on"]["push"]["branches"],
            ["GSoC_2026"],
        )
        self.assertIn("pull_request", workflow["on"])
        self.assertNotIn("secrets", workflow_text.lower())
        self.assertNotIn("continue-on-error", workflow_text)
        self.assertNotIn("paths-ignore", workflow_text)

        for job_id, job in workflow["jobs"].items():
            self.assertEqual(job["name"], job_id)
            self.assertEqual(job["runs-on"], "ubuntu-24.04")
            self.assertNotIn("strategy", job)
            if job_id != "ci-contract":
                self.assertNotIn("if", job)

        contract = workflow["jobs"]["ci-contract"]
        self.assertEqual(contract["if"], "always()")
        self.assertEqual(set(contract["needs"]), preceding_jobs)
        contract_script = "\n".join(
            step.get("run", "")
            for step in contract["steps"]
            if isinstance(step, dict)
        )
        for job_id in sorted(preceding_jobs):
            self.assertIn(f"needs['{job_id}'].result", contract_script)
            self.assertIn("success", contract_script)

        uses_lines = [
            line.strip()
            for line in workflow_text.splitlines()
            if line.strip().startswith("uses:")
        ]
        self.assertTrue(uses_lines)
        for line in uses_lines:
            self.assertRegex(
                line,
                r"^uses: [A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40} +# v[0-9]",
            )
        self.assertIn(
            "actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2",
            workflow_text,
        )
        self.assertIn(
            "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1",
            workflow_text,
        )

    def test_field_build_inputs_are_platform_specific_and_immutable(self) -> None:
        policy = json.loads(
            (REPO_ROOT / "deploy/deployment-policy.json").read_text(encoding="utf-8")
        )
        self.assertEqual(policy["field_build"]["platform"], "linux/amd64")
        self.assertEqual(
            policy["field_build"]["dockerfiles"],
            [
                "docker/tarpits/Dockerfile",
                "docker/prometheus/Dockerfile",
            ],
        )

        from_pattern = re.compile(
            r"^FROM [A-Za-z0-9./_-]+:[A-Za-z0-9._-]+"
            r"@sha256:[0-9a-f]{64}(?: AS [A-Za-z0-9._-]+)?$"
        )
        for relative_path in policy["field_build"]["dockerfiles"]:
            dockerfile = (REPO_ROOT / relative_path).read_text(encoding="utf-8")
            from_lines = [
                line
                for line in dockerfile.splitlines()
                if line.startswith("FROM ")
            ]
            self.assertTrue(from_lines)
            for line in from_lines:
                self.assertRegex(line, from_pattern)
            for forbidden in ("apt ", "apt-get ", "apk ", "curl ", "wget ", "git clone"):
                self.assertNotIn(forbidden, dockerfile)

        go_dockerfile = (
            REPO_ROOT / "docker/prometheus/Dockerfile"
        ).read_text(encoding="utf-8")
        self.assertIn("golang:1.23.9-bookworm@sha256:", go_dockerfile)
        self.assertIn("GOTOOLCHAIN=local", go_dockerfile)
        self.assertIn("GOFLAGS=-mod=readonly", go_dockerfile)
        self.assertIn("go build -mod=readonly", go_dockerfile)
        self.assertIn("sha256sum -c", go_dockerfile)

        field_compose = (
            REPO_ROOT / "docker-compose.field.yml"
        ).read_text(encoding="utf-8")
        class ComposeLoader(yaml.SafeLoader):
            pass

        ComposeLoader.add_constructor(
            "!override",
            lambda loader, node: loader.construct_sequence(node),
        )
        parsed_field_compose = yaml.load(field_compose, Loader=ComposeLoader)
        supported_services = {
            "prometheus-exporter",
            "telnet_pit",
            "mqtt_pit",
            "prometheus",
            "grafana",
            "cadvisor",
        }
        self.assertEqual(
            {
                name
                for name, service in parsed_field_compose["services"].items()
                if service.get("platform") == "linux/amd64"
            },
            supported_services,
        )
        compose_image_lines = [
            line.strip()
            for line in field_compose.splitlines()
            if line.strip().startswith("image:")
        ]
        self.assertEqual(len(compose_image_lines), 3)
        for line in compose_image_lines:
            self.assertRegex(
                line,
                r"^image: [A-Za-z0-9./_-]+:[A-Za-z0-9._-]+"
                r"@sha256:[0-9a-f]{64}$",
            )


class DeploymentOperatorCliTests(unittest.TestCase):
    def test_help_is_side_effect_free(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            output_base = Path(temporary_directory) / "evidence"
            environment = os.environ.copy()
            environment["VPS_FIELD_ENV_FILE"] = str(
                Path(temporary_directory) / "must-not-be-read.env"
            )

            completed = subprocess.run(
                [
                    str(REPO_ROOT / "scripts/vps_field_deploy.sh"),
                    "--help",
                    "--output-dir",
                    str(output_base),
                ],
                cwd=REPO_ROOT,
                env=environment,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 0)
            self.assertIn("usage: vps_field_deploy.sh", completed.stdout)
            self.assertIn("--check-only", completed.stdout)
            self.assertEqual(completed.stderr, "")
            self.assertFalse(output_base.exists())

    def test_invalid_commit_is_blocked_with_matching_partial_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            output_base = Path(temporary_directory) / "evidence"

            completed = subprocess.run(
                [
                    str(REPO_ROOT / "scripts/vps_field_deploy.sh"),
                    "--check-only",
                    "--commit",
                    "not-a-full-sha",
                    "--output-dir",
                    str(output_base),
                    "--format",
                    "json",
                ],
                cwd=REPO_ROOT,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 2)
            console_result = json.loads(completed.stdout)
            self.assertEqual(console_result["outcome"], "BLOCKED")
            self.assertEqual(console_result["exit_code"], 2)
            self.assertEqual(console_result["target_state"], "CI_VALIDATED")
            self.assertIsNone(console_result["highest_state"])
            self.assertFalse(console_result["remote_mutation_occurred"])

            run_directories = list((output_base / "deployments").iterdir())
            self.assertEqual(len(run_directories), 1)
            run_directory = run_directories[0]
            self.assertEqual(
                stat.S_IMODE(run_directory.stat().st_mode),
                0o700,
            )

            result_path = run_directory / "result.json"
            summary_path = run_directory / "summary.md"
            index_path = run_directory / "evidence-index.json"
            self.assertEqual(
                json.loads(result_path.read_text(encoding="utf-8")),
                console_result,
            )
            self.assertTrue(summary_path.is_file())
            self.assertTrue(index_path.is_file())
            for artifact in (result_path, summary_path, index_path):
                self.assertEqual(stat.S_IMODE(artifact.stat().st_mode), 0o600)

            result_schema = json.loads(
                (
                    REPO_ROOT / "deploy/schemas/deployment-result.schema.json"
                ).read_text(encoding="utf-8")
            )
            index_schema = json.loads(
                (
                    REPO_ROOT / "deploy/schemas/evidence-index.schema.json"
                ).read_text(encoding="utf-8")
            )
            Draft202012Validator(result_schema).validate(console_result)
            index = json.loads(index_path.read_text(encoding="utf-8"))
            Draft202012Validator(index_schema).validate(index)
            indexed = {
                artifact["filename"]: artifact
                for artifact in index["artifacts"]
            }
            for artifact in (result_path, summary_path):
                entry = indexed[artifact.name]
                content = artifact.read_bytes()
                self.assertEqual(entry["collection_status"], "COLLECTED")
                self.assertEqual(entry["size_bytes"], len(content))
                self.assertEqual(
                    entry["sha256"],
                    hashlib.sha256(content).hexdigest(),
                )
            self.assertNotIn("evidence-index.json", indexed)
            self.assertFalse(
                any(path.name.startswith(".") for path in run_directory.iterdir())
            )

    def test_check_only_warns_about_untracked_files_without_loading_target(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            output_base = Path(temporary_directory) / "evidence"
            commit = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=REPO_ROOT,
                text=True,
                capture_output=True,
                check=True,
            ).stdout.strip()
            environment = os.environ.copy()
            environment["VPS_FIELD_ENV_FILE"] = str(
                Path(temporary_directory) / "must-not-be-read.env"
            )

            with tempfile.TemporaryDirectory(
                prefix=".deployment-controller-untracked-",
                dir=REPO_ROOT,
            ) as untracked_directory:
                (Path(untracked_directory) / "fixture.txt").write_text(
                    "untracked test fixture\n",
                    encoding="utf-8",
                )
                completed = subprocess.run(
                    [
                        str(REPO_ROOT / "scripts/vps_field_deploy.sh"),
                        "--check-only",
                        "--commit",
                        commit,
                        "--output-dir",
                        str(output_base),
                        "--format",
                        "json",
                    ],
                    cwd=REPO_ROOT,
                    env=environment,
                    text=True,
                    capture_output=True,
                    check=False,
                )

            self.assertEqual(completed.returncode, 2)
            result = json.loads(completed.stdout)
            self.assertEqual(result["outcome"], "BLOCKED")
            self.assertIn(
                "WARNING",
                [check["status"] for check in result["checks"]],
            )
            self.assertFalse(result["remote_mutation_occurred"])

    def test_symlinked_evidence_base_emits_redacted_error_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_path = Path(temporary_directory)
            actual_output = temporary_path / "actual"
            actual_output.mkdir()
            output_symlink = temporary_path / "evidence"
            output_symlink.symlink_to(actual_output, target_is_directory=True)

            completed = subprocess.run(
                [
                    str(REPO_ROOT / "scripts/vps_field_deploy.sh"),
                    "--check-only",
                    "--commit",
                    "1" * 40,
                    "--output-dir",
                    str(output_symlink),
                    "--format",
                    "json",
                ],
                cwd=REPO_ROOT,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 5)
            self.assertEqual(completed.stdout, "")
            fallback = json.loads(completed.stderr)
            self.assertEqual(fallback["outcome"], "ERROR")
            self.assertEqual(fallback["exit_code"], 5)
            self.assertFalse(fallback["remote_mutation_occurred"])
            self.assertFalse(fallback["field_services_running"])
            self.assertNotIn(str(actual_output), completed.stderr)
            self.assertFalse(any(actual_output.iterdir()))

    def test_unknown_argument_is_blocked_with_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            output_base = Path(temporary_directory) / "evidence"

            completed = subprocess.run(
                [
                    str(REPO_ROOT / "scripts/vps_field_deploy.sh"),
                    "--unknown-option",
                    "--output-dir",
                    str(output_base),
                    "--format",
                    "json",
                ],
                cwd=REPO_ROOT,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 2)
            result = json.loads(completed.stdout)
            self.assertEqual(result["outcome"], "BLOCKED")
            self.assertEqual(result["exit_code"], 2)
            self.assertEqual(result["checks"][-1]["check_id"], "cli_arguments")
            self.assertEqual(result["checks"][-1]["status"], "BLOCKER")
            run_directory = next((output_base / "deployments").iterdir())
            self.assertTrue((run_directory / "result.json").is_file())
            self.assertEqual(completed.stderr, "")


class FixedClock:
    def now(self) -> datetime:
        return datetime(2026, 7, 30, 1, 2, 3, tzinfo=timezone.utc)


class FixedRandomSource:
    def run_suffix(self) -> str:
        return "a1b2c3"


class ProvenRepository:
    def verify_candidate(self, commit: str, policy: dict[str, object]) -> CandidateVerification:
        return CandidateVerification(
            passed=True,
            protected_hashes={
                "scripts/vps_field_deploy.sh": "a" * 64,
            },
            warnings=(),
            blocker=None,
        )

    def target_file_is_ignored(self, path: Path) -> bool:
        return True


class NotIgnoredRepository(ProvenRepository):
    def target_file_is_ignored(self, path: Path) -> bool:
        return False


class ProvenTrustedCi:
    def verify(self, commit: str, policy: dict[str, object]) -> CiVerification:
        return CiVerification(
            passed=True,
            proof=successful_ci_proof(commit),
            blocker=None,
        )


class MalfunctioningTrustedCi:
    def verify(self, commit: str, policy: dict[str, object]) -> CiVerification:
        return CiVerification(
            passed=False,
            proof={},
            blocker="Trusted GitHub Actions evidence retrieval malfunctioned.",
            outcome="ERROR",
        )


def successful_ci_proof(
    commit: str,
    run_attempt: int = 1,
) -> dict[str, object]:
    required_jobs = [
        "build-unit",
        "deployment-controller",
        "shell-quality",
        "configuration-policy",
        "container-builds",
        "deterministic-smoke",
        "ci-contract",
    ]
    return {
        "schema_version": 1,
        "repository": "honeynet/EventHorizon",
        "workflow_path": ".github/workflows/ci.yml",
        "workflow_id": 456,
        "run_id": 123,
        "run_attempt": run_attempt,
        "head_sha": commit,
        "head_branch": "GSoC_2026",
        "event": "push",
        "status": "completed",
        "conclusion": "success",
        "created_at": "2026-07-30T01:00:00Z",
        "run_started_at": "2026-07-30T01:01:00Z",
        "updated_at": "2026-07-30T01:10:00Z",
        "jobs": [
            {
                "name": name,
                "status": "completed",
                "conclusion": "success",
                "started_at": "2026-07-30T01:01:00Z",
                "completed_at": "2026-07-30T01:09:00Z",
                "run_attempt": run_attempt,
            }
            for name in required_jobs
        ],
        "url": "https://github.com/honeynet/EventHorizon/actions/runs/123",
    }


class StaticGitHubActionsApi:
    def __init__(
        self,
        runs: list[dict[str, object]],
        jobs: list[dict[str, object]],
    ) -> None:
        self.runs = runs
        self.jobs = jobs
        self.job_requests: list[tuple[str, int, int]] = []

    def list_workflow_runs(
        self,
        repository: str,
        workflow_path: str,
        event: str,
        head_sha: str,
        head_branch: str,
    ) -> list[dict[str, object]]:
        return self.runs

    def list_run_attempt_jobs(
        self,
        repository: str,
        run_id: int,
        run_attempt: int,
    ) -> list[dict[str, object]]:
        self.job_requests.append((repository, run_id, run_attempt))
        return self.jobs


class BrokenGitHubActionsApi(StaticGitHubActionsApi):
    def list_workflow_runs(
        self,
        repository: str,
        workflow_path: str,
        event: str,
        head_sha: str,
        head_branch: str,
    ) -> list[dict[str, object]]:
        raise GitHubApiError("network details must not escape")


class TrustedGitHubActionsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.commit = "1" * 40
        self.policy = json.loads(
            (REPO_ROOT / "deploy/deployment-policy.json").read_text(encoding="utf-8")
        )
        proof = successful_ci_proof(self.commit, run_attempt=3)
        self.run_document = {
            "id": proof["run_id"],
            "workflow_id": proof["workflow_id"],
            "run_attempt": proof["run_attempt"],
            "head_sha": proof["head_sha"],
            "head_branch": proof["head_branch"],
            "event": proof["event"],
            "status": proof["status"],
            "conclusion": proof["conclusion"],
            "created_at": proof["created_at"],
            "run_started_at": proof["run_started_at"],
            "updated_at": proof["updated_at"],
            "path": ".github/workflows/ci.yml@refs/heads/GSoC_2026",
            "html_url": proof["url"],
            "repository": {"full_name": proof["repository"]},
        }
        self.jobs = [
            {
                **job,
                "head_sha": self.commit,
            }
            for job in proof["jobs"]
        ]

    def test_exact_push_run_and_latest_attempt_produce_ci_proof(self) -> None:
        api = StaticGitHubActionsApi([self.run_document], self.jobs)

        verification = TrustedGitHubActions(api).verify(
            self.commit,
            self.policy,
        )

        self.assertTrue(verification.passed)
        self.assertIsNone(verification.blocker)
        self.assertEqual(verification.proof["run_attempt"], 3)
        self.assertEqual(
            api.job_requests,
            [("honeynet/EventHorizon", 123, 3)],
        )
        schema = json.loads(
            (
                REPO_ROOT / "deploy/schemas/ci-proof.schema.json"
            ).read_text(encoding="utf-8")
        )
        Draft202012Validator(
            schema,
            format_checker=Draft202012Validator.FORMAT_CHECKER,
        ).validate(verification.proof)

    def test_missing_or_non_push_proof_is_blocked(self) -> None:
        for name, runs in (
            ("missing", []),
            (
                "pull-request",
                [dict(self.run_document, event="pull_request")],
            ),
            (
                "wrong-branch",
                [dict(self.run_document, head_branch="main")],
            ),
            (
                "failed-workflow",
                [dict(self.run_document, conclusion="failure")],
            ),
        ):
            with self.subTest(case=name):
                verification = TrustedGitHubActions(
                    StaticGitHubActionsApi(runs, self.jobs)
                ).verify(self.commit, self.policy)
                self.assertFalse(verification.passed)
                self.assertEqual(verification.outcome, "BLOCKED")
                self.assertEqual(verification.proof, {})

    def test_missing_skipped_or_dynamic_job_is_blocked(self) -> None:
        job_cases = (
            ("missing", self.jobs[:-1]),
            (
                "skipped",
                [dict(self.jobs[0], conclusion="skipped"), *self.jobs[1:]],
            ),
            (
                "dynamic-name",
                [dict(self.jobs[0], name="build-unit (linux)"), *self.jobs[1:]],
            ),
        )
        for name, jobs in job_cases:
            with self.subTest(case=name):
                verification = TrustedGitHubActions(
                    StaticGitHubActionsApi([self.run_document], jobs)
                ).verify(self.commit, self.policy)
                self.assertFalse(verification.passed)
                self.assertEqual(verification.outcome, "BLOCKED")

    def test_api_malfunction_is_error_without_retaining_details(self) -> None:
        verification = TrustedGitHubActions(
            BrokenGitHubActionsApi([], [])
        ).verify(self.commit, self.policy)

        self.assertFalse(verification.passed)
        self.assertEqual(verification.outcome, "ERROR")
        self.assertNotIn("network details", verification.blocker or "")


class ReadyRemote:
    def preflight(
        self,
        configuration: object,
        commit: str,
        policy: dict[str, object],
    ) -> RemotePreflightVerification:
        return RemotePreflightVerification(
            passed=True,
            evidence={
                "target_alias": "field-host",
                "result": "PASS",
            },
            blocker=None,
        )


class DeclinedAuthorization:
    def authorize(self, phrase: str) -> AuthorizationDecision:
        return AuthorizationDecision(authorized=False)


class InterruptedAuthorization:
    def authorize(self, phrase: str) -> AuthorizationDecision:
        raise KeyboardInterrupt


class DeploymentControllerApiTests(unittest.TestCase):
    def test_run_returns_a_deterministic_structured_result(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            request = DeploymentRequest(
                check_only=True,
                commit="invalid",
                env_file=None,
                output_dir=Path(temporary_directory) / "evidence",
            )
            adapters = ControllerAdapters(
                clock=FixedClock(),
                randomness=FixedRandomSource(),
            )

            result = run(request, adapters)

            self.assertIsInstance(result, DeploymentResult)
            self.assertEqual(result.run_id, "deploy-20260730T010203Z-a1b2c3")
            self.assertEqual(result.outcome, "BLOCKED")
            self.assertEqual(result.exit_code, 2)
            self.assertEqual(result.started_utc, "2026-07-30T01:02:03Z")
            self.assertEqual(result.finished_utc, "2026-07-30T01:02:03Z")

    def test_existing_safe_output_base_keeps_its_permissions(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            output_directory = Path(temporary_directory) / "evidence"
            output_directory.mkdir(mode=0o755)
            output_directory.chmod(0o755)

            result = run(
                DeploymentRequest(
                    check_only=True,
                    commit="invalid",
                    env_file=None,
                    output_dir=output_directory,
                ),
                ControllerAdapters(
                    clock=FixedClock(),
                    randomness=FixedRandomSource(),
                ),
            )

            self.assertEqual(
                stat.S_IMODE(output_directory.stat().st_mode),
                0o755,
            )
            run_directory = (
                output_directory / "deployments" / result.run_id
            )
            self.assertEqual(
                stat.S_IMODE(run_directory.stat().st_mode),
                0o700,
            )

    def test_run_identifier_collision_preserves_existing_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            output_directory = Path(temporary_directory) / "evidence"
            request = DeploymentRequest(
                check_only=True,
                commit="invalid",
                env_file=None,
                output_dir=output_directory,
            )
            adapters = ControllerAdapters(
                clock=FixedClock(),
                randomness=FixedRandomSource(),
            )

            first_result = run(request, adapters)
            first_result_path = (
                output_directory
                / "deployments"
                / first_result.run_id
                / "result.json"
            )
            first_content = first_result_path.read_bytes()

            with self.assertRaises(EvidenceError):
                run(request, adapters)

            self.assertEqual(first_result_path.read_bytes(), first_content)
            self.assertEqual(
                list((output_directory / "deployments").iterdir()),
                [first_result_path.parent],
            )

    def test_check_only_passes_after_candidate_and_ci_are_proven(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            commit = "1" * 40
            request = DeploymentRequest(
                check_only=True,
                commit=commit,
                env_file=None,
                output_dir=Path(temporary_directory) / "evidence",
            )
            adapters = ControllerAdapters(
                clock=FixedClock(),
                randomness=FixedRandomSource(),
                repository=ProvenRepository(),
                trusted_ci=ProvenTrustedCi(),
            )

            result = run(request, adapters)

            self.assertEqual(result.target_state, "CI_VALIDATED")
            self.assertEqual(result.highest_state, "CI_VALIDATED")
            self.assertEqual(result.outcome, "PASS")
            self.assertEqual(result.exit_code, 0)
            self.assertFalse(result.remote_mutation_occurred)
            self.assertFalse(result.field_services_running)
            ci_proof = json.loads(
                (
                    Path(temporary_directory)
                    / "evidence"
                    / "deployments"
                    / result.run_id
                    / "ci-proof.json"
                ).read_text(encoding="utf-8")
            )
            ci_schema = json.loads(
                (
                    REPO_ROOT / "deploy/schemas/ci-proof.schema.json"
                ).read_text(encoding="utf-8")
            )
            Draft202012Validator(
                ci_schema,
                format_checker=Draft202012Validator.FORMAT_CHECKER,
            ).validate(ci_proof)

    def test_candidate_state_survives_a_later_ci_proof_blocker(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            result = run(
                DeploymentRequest(
                    check_only=True,
                    commit="1" * 40,
                    env_file=None,
                    output_dir=Path(temporary_directory) / "evidence",
                ),
                ControllerAdapters(
                    clock=FixedClock(),
                    randomness=FixedRandomSource(),
                    repository=ProvenRepository(),
                ),
            )

            self.assertEqual(result.outcome, "BLOCKED")
            self.assertEqual(result.exit_code, 2)
            self.assertEqual(result.highest_state, "DEPLOYMENT_CANDIDATE")
            self.assertFalse(result.remote_mutation_occurred)

    def test_ci_infrastructure_malfunction_preserves_candidate_and_is_error(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            result = run(
                DeploymentRequest(
                    check_only=True,
                    commit="1" * 40,
                    env_file=None,
                    output_dir=Path(temporary_directory) / "evidence",
                ),
                ControllerAdapters(
                    clock=FixedClock(),
                    randomness=FixedRandomSource(),
                    repository=ProvenRepository(),
                    trusted_ci=MalfunctioningTrustedCi(),
                ),
            )

            self.assertEqual(result.outcome, "ERROR")
            self.assertEqual(result.exit_code, 5)
            self.assertEqual(result.highest_state, "DEPLOYMENT_CANDIDATE")
            trusted_check = next(
                check
                for check in result.checks
                if check.check_id == "trusted_ci"
            )
            self.assertEqual(trusted_check.status, "ERROR")

    def test_valid_target_data_passes_without_leaking_values(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_path = Path(temporary_directory)
            ssh_key = temporary_path / "operator_key"
            ssh_key.write_text("test-only-private-key\n", encoding="utf-8")
            ssh_key.chmod(0o600)
            target_file = temporary_path / "field.env"
            target_file.write_text(
                "\n".join(
                    (
                        "TARGET_ALIAS=field-host",
                        "VPS_HOST=198.51.100.10",
                        "VPS_USER=deploy",
                        "VPS_SSH_PORT=22",
                        f"VPS_SSH_KEY={ssh_key}",
                        "VPS_DEPLOY_DIR=/srv/eventhorizon-field",
                        "VPS_PROJECT_NAME=eventhorizon-field",
                        "ADMIN_SOURCE_CIDR=203.0.113.9/32",
                        "FIELD_TARPIT_CPU_LIMIT=0.50",
                        "FIELD_TARPIT_MEMORY_LIMIT=",
                        "",
                    )
                ),
                encoding="utf-8",
            )
            target_file.chmod(0o600)
            output_directory = temporary_path / "evidence"
            request = DeploymentRequest(
                check_only=False,
                commit="1" * 40,
                env_file=target_file,
                output_dir=output_directory,
            )
            adapters = ControllerAdapters(
                clock=FixedClock(),
                randomness=FixedRandomSource(),
                repository=ProvenRepository(),
                trusted_ci=ProvenTrustedCi(),
            )

            result = run(request, adapters)

            self.assertEqual(result.target_state, "ENVIRONMENT_VALIDATED")
            self.assertEqual(result.highest_state, "CI_VALIDATED")
            self.assertEqual(result.outcome, "BLOCKED")
            self.assertEqual(result.exit_code, 2)
            target_checks = [
                check
                for check in result.checks
                if check.check_id == "target_configuration"
            ]
            self.assertEqual(len(target_checks), 1)
            self.assertEqual(target_checks[0].status, "PASS")
            self.assertIn(
                "remote preflight",
                result.next_action.lower(),
            )

            retained = json.dumps(result.to_dict())
            run_directory = (
                output_directory / "deployments" / result.run_id
            )
            for artifact in run_directory.iterdir():
                retained += artifact.read_text(encoding="utf-8")
            for sensitive_value in (
                "198.51.100.10",
                "203.0.113.9/32",
                str(ssh_key),
                "test-only-private-key",
            ):
                self.assertNotIn(sensitive_value, retained)

    def test_target_file_security_and_strict_data_violations_are_blocked(
        self,
    ) -> None:
        cases = (
            ("insecure-mode", "normal", 0o644, ProvenRepository(), "mode"),
            ("symlink", "symlink", 0o600, ProvenRepository(), "symlink"),
            ("duplicate", "duplicate", 0o600, ProvenRepository(), "duplicate"),
            (
                "interpolation",
                "interpolation",
                0o600,
                ProvenRepository(),
                "strict data",
            ),
            (
                "not-ignored",
                "normal",
                0o600,
                NotIgnoredRepository(),
                "ignored by Git",
            ),
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_path = Path(temporary_directory)
            for name, mutation, mode, repository, expected_diagnostic in cases:
                with self.subTest(case=name):
                    case_directory = temporary_path / name
                    case_directory.mkdir()
                    case_directory.chmod(0o700)
                    ssh_key = case_directory / "operator_key"
                    ssh_key.write_text("test-only-private-key\n", encoding="utf-8")
                    ssh_key.chmod(0o600)
                    lines = [
                        "TARGET_ALIAS=field-host",
                        "VPS_HOST=198.51.100.10",
                        "VPS_USER=deploy",
                        "VPS_SSH_PORT=22",
                        f"VPS_SSH_KEY={ssh_key}",
                        "VPS_DEPLOY_DIR=/srv/eventhorizon-field",
                        "VPS_PROJECT_NAME=eventhorizon-field",
                        "ADMIN_SOURCE_CIDR=203.0.113.9/32",
                        "FIELD_TARPIT_CPU_LIMIT=0.50",
                        "FIELD_TARPIT_MEMORY_LIMIT=",
                    ]
                    if mutation == "duplicate":
                        lines.append("TARGET_ALIAS=second-field-host")
                    elif mutation == "interpolation":
                        lines[1] = "VPS_HOST=$(DO_NOT_RUN_MARKER)"

                    target_file = case_directory / "field.env"
                    if mutation == "symlink":
                        actual_target = case_directory / "actual-field.env"
                        actual_target.write_text(
                            "\n".join(lines) + "\n",
                            encoding="utf-8",
                        )
                        actual_target.chmod(0o600)
                        target_file.symlink_to(actual_target)
                    else:
                        target_file.write_text(
                            "\n".join(lines) + "\n",
                            encoding="utf-8",
                        )
                        target_file.chmod(mode)

                    output_directory = case_directory / "evidence"
                    result = run(
                        DeploymentRequest(
                            check_only=False,
                            commit="1" * 40,
                            env_file=target_file,
                            output_dir=output_directory,
                        ),
                        ControllerAdapters(
                            clock=FixedClock(),
                            randomness=FixedRandomSource(),
                            repository=repository,
                            trusted_ci=ProvenTrustedCi(),
                        ),
                    )

                    self.assertEqual(result.outcome, "BLOCKED")
                    self.assertEqual(result.exit_code, 2)
                    self.assertFalse(result.remote_mutation_occurred)
                    target_check = next(
                        check
                        for check in result.checks
                        if check.check_id == "target_configuration"
                    )
                    self.assertEqual(target_check.status, "BLOCKER")
                    self.assertIn(
                        expected_diagnostic,
                        target_check.observed or "",
                    )
                    retained = json.dumps(result.to_dict())
                    for artifact in (
                        output_directory / "deployments" / result.run_id
                    ).iterdir():
                        retained += artifact.read_text(encoding="utf-8")
                    self.assertNotIn("DO_NOT_RUN_MARKER", retained)

    def test_control_characters_in_target_data_are_blocked_with_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_path = Path(temporary_directory)
            target_file = temporary_path / "field.env"
            target_file.write_bytes(
                b"\n".join(
                    (
                        b"TARGET_ALIAS=field-host",
                        b"VPS_HOST=198.51.100.10",
                        b"VPS_USER=deploy",
                        b"VPS_SSH_PORT=22",
                        b"VPS_SSH_KEY=/tmp/operator\x00key",
                        b"VPS_DEPLOY_DIR=/srv/eventhorizon-field",
                        b"VPS_PROJECT_NAME=eventhorizon-field",
                        b"ADMIN_SOURCE_CIDR=203.0.113.9/32",
                        b"FIELD_TARPIT_CPU_LIMIT=0.50",
                        b"FIELD_TARPIT_MEMORY_LIMIT=",
                    )
                )
                + b"\n"
            )
            target_file.chmod(0o600)
            request = DeploymentRequest(
                check_only=False,
                commit="1" * 40,
                env_file=target_file,
                output_dir=temporary_path / "evidence",
            )
            adapters = ControllerAdapters(
                clock=FixedClock(),
                randomness=FixedRandomSource(),
                repository=ProvenRepository(),
                trusted_ci=ProvenTrustedCi(),
            )

            result = run(request, adapters)

            self.assertEqual(result.outcome, "BLOCKED")
            self.assertEqual(result.exit_code, 2)
            target_check = next(
                check
                for check in result.checks
                if check.check_id == "target_configuration"
            )
            self.assertEqual(target_check.status, "BLOCKER")
            self.assertIn("strict data", target_check.observed or "")
            self.assertTrue(
                (
                    temporary_path
                    / "evidence"
                    / "deployments"
                    / result.run_id
                    / "result.json"
                ).is_file()
            )

    def test_unknown_target_key_is_blocked_without_echoing_its_name(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_path = Path(temporary_directory)
            ssh_key = temporary_path / "operator_key"
            ssh_key.write_text("test-only-private-key\n", encoding="utf-8")
            ssh_key.chmod(0o600)
            secret_marker = "DO_NOT_RETAIN_MARKER"
            target_file = temporary_path / "field.env"
            target_file.write_text(
                "\n".join(
                    (
                        "TARGET_ALIAS=field-host",
                        "VPS_HOST=198.51.100.10",
                        "VPS_USER=deploy",
                        "VPS_SSH_PORT=22",
                        f"VPS_SSH_KEY={ssh_key}",
                        "VPS_DEPLOY_DIR=/srv/eventhorizon-field",
                        "VPS_PROJECT_NAME=eventhorizon-field",
                        "ADMIN_SOURCE_CIDR=203.0.113.9/32",
                        "FIELD_TARPIT_CPU_LIMIT=0.50",
                        "FIELD_TARPIT_MEMORY_LIMIT=",
                        f"{secret_marker}=secret",
                        "",
                    )
                ),
                encoding="utf-8",
            )
            target_file.chmod(0o600)
            output_directory = temporary_path / "evidence"
            result = run(
                DeploymentRequest(
                    check_only=False,
                    commit="1" * 40,
                    env_file=target_file,
                    output_dir=output_directory,
                ),
                ControllerAdapters(
                    clock=FixedClock(),
                    randomness=FixedRandomSource(),
                    repository=ProvenRepository(),
                    trusted_ci=ProvenTrustedCi(),
                ),
            )

            self.assertEqual(result.outcome, "BLOCKED")
            retained = json.dumps(result.to_dict())
            run_directory = output_directory / "deployments" / result.run_id
            for artifact in run_directory.iterdir():
                retained += artifact.read_text(encoding="utf-8")
            self.assertNotIn(secret_marker, retained)

    def test_operator_refusal_is_cancelled_without_remote_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_path = Path(temporary_directory)
            ssh_key = temporary_path / "operator_key"
            ssh_key.write_text("test-only-private-key\n", encoding="utf-8")
            ssh_key.chmod(0o600)
            target_file = temporary_path / "field.env"
            target_file.write_text(
                "\n".join(
                    (
                        "TARGET_ALIAS=field-host",
                        "VPS_HOST=198.51.100.10",
                        "VPS_USER=deploy",
                        "VPS_SSH_PORT=22",
                        f"VPS_SSH_KEY={ssh_key}",
                        "VPS_DEPLOY_DIR=/srv/eventhorizon-field",
                        "VPS_PROJECT_NAME=eventhorizon-field",
                        "ADMIN_SOURCE_CIDR=203.0.113.9/32",
                        "FIELD_TARPIT_CPU_LIMIT=0.50",
                        "FIELD_TARPIT_MEMORY_LIMIT=",
                        "",
                    )
                ),
                encoding="utf-8",
            )
            target_file.chmod(0o600)
            output_directory = temporary_path / "evidence"
            request = DeploymentRequest(
                check_only=False,
                commit="1" * 40,
                env_file=target_file,
                output_dir=output_directory,
            )
            adapters = ControllerAdapters(
                clock=FixedClock(),
                randomness=FixedRandomSource(),
                repository=ProvenRepository(),
                trusted_ci=ProvenTrustedCi(),
                remote=ReadyRemote(),
                authorization=DeclinedAuthorization(),
            )

            result = run(request, adapters)

            self.assertEqual(result.highest_state, "CI_VALIDATED")
            self.assertEqual(result.outcome, "CANCELLED")
            self.assertEqual(result.exit_code, 6)
            self.assertFalse(result.remote_mutation_occurred)
            self.assertFalse(result.field_services_running)
            authorization_path = (
                output_directory
                / "deployments"
                / result.run_id
                / "authorization.json"
            )
            authorization = json.loads(
                authorization_path.read_text(encoding="utf-8")
            )
            self.assertEqual(
                set(authorization),
                {
                    "authorization_attested",
                    "firewall_policy_reviewed",
                    "admin_source_restriction_attested",
                    "attestation_utc",
                    "deployment_commit",
                    "target_alias",
                    "observed_public_ports",
                    "observed_private_ports",
                    "result",
                },
            )
            self.assertFalse(authorization["authorization_attested"])
            self.assertEqual(authorization["result"], "CANCELLED")

    def test_sigint_during_authorization_is_cancelled_with_exit_130(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_path = Path(temporary_directory)
            ssh_key = temporary_path / "operator_key"
            ssh_key.write_text("test-only-private-key\n", encoding="utf-8")
            ssh_key.chmod(0o600)
            target_file = temporary_path / "field.env"
            target_file.write_text(
                "\n".join(
                    (
                        "TARGET_ALIAS=field-host",
                        "VPS_HOST=198.51.100.10",
                        "VPS_USER=deploy",
                        "VPS_SSH_PORT=22",
                        f"VPS_SSH_KEY={ssh_key}",
                        "VPS_DEPLOY_DIR=/srv/eventhorizon-field",
                        "VPS_PROJECT_NAME=eventhorizon-field",
                        "ADMIN_SOURCE_CIDR=203.0.113.9/32",
                        "FIELD_TARPIT_CPU_LIMIT=0.50",
                        "FIELD_TARPIT_MEMORY_LIMIT=",
                        "",
                    )
                ),
                encoding="utf-8",
            )
            target_file.chmod(0o600)
            output_directory = temporary_path / "evidence"
            request = DeploymentRequest(
                check_only=False,
                commit="1" * 40,
                env_file=target_file,
                output_dir=output_directory,
            )
            adapters = ControllerAdapters(
                clock=FixedClock(),
                randomness=FixedRandomSource(),
                repository=ProvenRepository(),
                trusted_ci=ProvenTrustedCi(),
                remote=ReadyRemote(),
                authorization=InterruptedAuthorization(),
            )

            result = run(request, adapters)

            self.assertEqual(result.highest_state, "CI_VALIDATED")
            self.assertEqual(result.outcome, "CANCELLED")
            self.assertEqual(result.exit_code, 130)
            self.assertFalse(result.remote_mutation_occurred)
            authorization = json.loads(
                (
                    output_directory
                    / "deployments"
                    / result.run_id
                    / "authorization.json"
                ).read_text(encoding="utf-8")
            )
            self.assertFalse(authorization["authorization_attested"])
            self.assertEqual(authorization["result"], "CANCELLED")


class LocalGitRepositoryIntegrationTests(unittest.TestCase):
    def test_candidate_refreshes_and_uses_the_trusted_upstream_ref(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_path = Path(temporary_directory)
            repository_path = temporary_path / "repository"
            upstream_path = temporary_path / "upstream.git"
            repository_path.mkdir()
            subprocess.run(
                ["git", "init", "--bare", "-q", str(upstream_path)],
                check=True,
                capture_output=True,
            )

            def git(*arguments: str) -> str:
                completed = subprocess.run(
                    ["git", *arguments],
                    cwd=repository_path,
                    text=True,
                    capture_output=True,
                    check=True,
                )
                return completed.stdout.strip()

            trusted_url = "git@github.com:honeynet/EventHorizon.git"
            git("init", "-q")
            git("config", "user.name", "Controller Test")
            git("config", "user.email", "controller@example.invalid")
            git(
                "config",
                f"url.{upstream_path.as_uri()}.insteadOf",
                trusted_url,
            )
            git("remote", "add", "upstream", trusted_url)
            protected = repository_path / "protected/controller.txt"
            protected.parent.mkdir()
            protected.write_text("trusted controller\n", encoding="utf-8")
            unrelated = repository_path / "unrelated.txt"
            unrelated.write_text("candidate\n", encoding="utf-8")
            git("add", ".")
            git("commit", "-qm", "candidate")
            deployment_commit = git("rev-parse", "HEAD")
            unrelated.write_text("approved branch tip\n", encoding="utf-8")
            git("add", "unrelated.txt")
            git("commit", "-qm", "new upstream tip")
            git("push", "-q", "upstream", "HEAD:refs/heads/GSoC_2026")

            verification = LocalGitRepository(repository_path).verify_candidate(
                deployment_commit,
                {
                    "trusted_repository": "honeynet/EventHorizon",
                    "trusted_remote": "upstream",
                    "approved_ref": "refs/remotes/upstream/GSoC_2026",
                    "protected_paths": ["protected/controller.txt"],
                },
            )

            self.assertTrue(verification.passed)
            self.assertIsNone(verification.blocker)
            self.assertEqual(
                git("rev-parse", "refs/remotes/upstream/GSoC_2026"),
                git("rev-parse", "HEAD"),
            )

            git(
                "config",
                "remote.upstream.url",
                "git@github.com:untrusted/EventHorizon.git",
            )
            rejected = LocalGitRepository(repository_path).verify_candidate(
                deployment_commit,
                {
                    "trusted_repository": "honeynet/EventHorizon",
                    "trusted_remote": "upstream",
                    "approved_ref": "refs/remotes/upstream/GSoC_2026",
                    "protected_paths": ["protected/controller.txt"],
                },
            )
            self.assertFalse(rejected.passed)
            self.assertEqual(
                rejected.blocker,
                "Configured trusted upstream remote is invalid.",
            )

    def test_non_tip_commit_allows_unrelated_changes_and_warns_untracked(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            repository_path = Path(temporary_directory) / "repository"
            repository_path.mkdir()

            def git(*arguments: str) -> str:
                completed = subprocess.run(
                    ["git", *arguments],
                    cwd=repository_path,
                    text=True,
                    capture_output=True,
                    check=True,
                )
                return completed.stdout.strip()

            git("init", "-q")
            git("config", "user.name", "Controller Test")
            git("config", "user.email", "controller@example.invalid")
            protected = repository_path / "protected/controller.txt"
            protected.parent.mkdir()
            protected.write_text("trusted controller\n", encoding="utf-8")
            unrelated = repository_path / "unrelated.txt"
            unrelated.write_text("first\n", encoding="utf-8")
            git("add", ".")
            git("commit", "-qm", "candidate")
            deployment_commit = git("rev-parse", "HEAD")

            unrelated.write_text("second\n", encoding="utf-8")
            git("add", "unrelated.txt")
            git("commit", "-qm", "new local head")
            git("branch", "approved")
            unrelated.write_text("uncommitted unrelated change\n", encoding="utf-8")
            (repository_path / "local-notes.md").write_text(
                "untracked and never deployed\n",
                encoding="utf-8",
            )

            verification = LocalGitRepository(repository_path).verify_candidate(
                deployment_commit,
                {
                    "approved_ref": "refs/heads/approved",
                    "protected_paths": ["protected/controller.txt"],
                },
            )

            self.assertTrue(verification.passed)
            self.assertIsNone(verification.blocker)
            self.assertEqual(
                verification.protected_hashes,
                {
                    "protected/controller.txt": hashlib.sha256(
                        b"trusted controller\n"
                    ).hexdigest()
                },
            )
            self.assertEqual(
                verification.warnings,
                (
                    "Repository contains untracked files; they are not deployed.",
                ),
            )

    def test_protected_change_blocks_without_hiding_untracked_warning(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            repository_path = Path(temporary_directory) / "repository"
            repository_path.mkdir()

            def git(*arguments: str) -> str:
                completed = subprocess.run(
                    ["git", *arguments],
                    cwd=repository_path,
                    text=True,
                    capture_output=True,
                    check=True,
                )
                return completed.stdout.strip()

            git("init", "-q")
            git("config", "user.name", "Controller Test")
            git("config", "user.email", "controller@example.invalid")
            protected = repository_path / "controller.txt"
            protected.write_text("reviewed\n", encoding="utf-8")
            git("add", "controller.txt")
            git("commit", "-qm", "candidate")
            deployment_commit = git("rev-parse", "HEAD")
            git("branch", "approved")

            protected.write_text("local change\n", encoding="utf-8")
            (repository_path / "notes.md").write_text("untracked\n", encoding="utf-8")

            verification = LocalGitRepository(repository_path).verify_candidate(
                deployment_commit,
                {
                    "approved_ref": "refs/heads/approved",
                    "protected_paths": ["controller.txt"],
                },
            )

            self.assertFalse(verification.passed)
            self.assertIn("controller.txt", verification.blocker or "")
            self.assertEqual(
                verification.warnings,
                (
                    "Repository contains untracked files; they are not deployed.",
                ),
            )

    def test_staged_protected_change_blocks_even_when_worktree_matches_commit(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            repository_path = Path(temporary_directory) / "repository"
            repository_path.mkdir()

            def git(*arguments: str) -> str:
                completed = subprocess.run(
                    ["git", *arguments],
                    cwd=repository_path,
                    text=True,
                    capture_output=True,
                    check=True,
                )
                return completed.stdout.strip()

            git("init", "-q")
            git("config", "user.name", "Controller Test")
            git("config", "user.email", "controller@example.invalid")
            protected = repository_path / "controller.txt"
            protected.write_text("reviewed\n", encoding="utf-8")
            git("add", "controller.txt")
            git("commit", "-qm", "candidate")
            deployment_commit = git("rev-parse", "HEAD")
            git("branch", "approved")

            protected.write_text("staged but unreviewed\n", encoding="utf-8")
            git("add", "controller.txt")
            protected.write_text("reviewed\n", encoding="utf-8")

            verification = LocalGitRepository(repository_path).verify_candidate(
                deployment_commit,
                {
                    "approved_ref": "refs/heads/approved",
                    "protected_paths": ["controller.txt"],
                },
            )

            self.assertFalse(verification.passed)
            self.assertIn("staged", verification.blocker or "")
            self.assertEqual(verification.warnings, ())


if __name__ == "__main__":
    unittest.main()
