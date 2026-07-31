import base64
import hashlib
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
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
    RemoteDeploymentExecution,
    RemoteDeploymentVerification,
    RemoteProbeExecution,
    RemotePreflightVerification,
    SshExactSourceDeployment,
    SshRemotePreflight,
    SystemSshDeploymentTransport,
    SystemSshProbeTransport,
    TargetConfiguration,
    TrustedGitHubActions,
    production_adapters,
    run,
)


REPO_ROOT = Path(__file__).resolve().parents[1]


def write_strict_target_configuration(
    directory: Path,
) -> tuple[Path, Path]:
    ssh_key = directory / "operator_key"
    ssh_key.write_text("test-only-private-key\n", encoding="utf-8")
    ssh_key.chmod(0o600)
    target_file = directory / "field.env"
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
    return target_file, ssh_key


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
        self.assertIn(
            "scripts/vps_field_remote_probe.py",
            policy["protected_paths"],
        )
        self.assertIn(
            "scripts/vps_field_remote_deploy.py",
            policy["protected_paths"],
        )
        self.assertIn(".github/workflows/ci.yml", policy["protected_paths"])
        self.assertIn(
            "deploy/schemas/remote-preflight.schema.json",
            policy["protected_paths"],
        )
        self.assertEqual(policy["remote_preflight_schema_version"], 1)
        self.assertEqual(policy["compose_config_schema_version"], 1)
        self.assertEqual(policy["deployment_manifest_schema_version"], 1)

    def test_phase_six_artifact_schemas_are_strict(self) -> None:
        compose_schema = json.loads(
            (
                REPO_ROOT / "deploy/schemas/compose-config.schema.json"
            ).read_text(encoding="utf-8")
        )
        manifest_schema = json.loads(
            (
                REPO_ROOT / "deploy/schemas/deployment-manifest.schema.json"
            ).read_text(encoding="utf-8")
        )
        port_map = {
            "cadvisor": ("127.0.0.1", 8081, 8080),
            "grafana": ("127.0.0.1", 3000, 3000),
            "mqtt_pit": ("0.0.0.0", 1883, 1883),
            "prometheus": ("127.0.0.1", 9090, 9090),
            "prometheus-exporter": ("127.0.0.1", 9101, 9101),
            "telnet_pit": ("0.0.0.0", 23, 23),
        }
        build_sources = {
            "mqtt_pit": "docker/tarpits/Dockerfile",
            "prometheus-exporter": "docker/prometheus/Dockerfile",
            "telnet_pit": "docker/tarpits/Dockerfile",
        }
        image_sources = {
            "cadvisor": "ghcr.io/google/cadvisor:v0.57.0@sha256:" + "3" * 64,
            "grafana": "grafana/grafana-oss:12.1.0@sha256:" + "2" * 64,
            "prometheus": "prom/prometheus:v3.5.0@sha256:" + "1" * 64,
        }
        services = []
        for name in (
            "cadvisor",
            "grafana",
            "mqtt_pit",
            "prometheus",
            "prometheus-exporter",
            "telnet_pit",
        ):
            host_ip, published, target = port_map[name]
            source_type = "BUILD" if name in build_sources else "PINNED_IMAGE"
            services.append(
                {
                    "name": name,
                    "source_type": source_type,
                    "source": (
                        build_sources.get(name) or image_sources[name]
                    ),
                    "platform": "linux/amd64",
                    "ports": [
                        {
                            "host_ip": host_ip,
                            "published": published,
                            "target": target,
                            "protocol": "tcp",
                        }
                    ],
                    "restart": "unless-stopped",
                    "logging_driver": (
                        "none" if name in {"mqtt_pit", "telnet_pit"}
                        else "json-file"
                    ),
                    "cpu_limit": (
                        "0.5" if name in {"mqtt_pit", "telnet_pit"} else None
                    ),
                    "memory_limit_bytes": (
                        268435456
                        if name in {"mqtt_pit", "telnet_pit"}
                        else None
                    ),
                    "privileged": name == "cadvisor",
                    "volumes": [],
                }
            )
        compose_config = {
            "schema_version": 1,
            "deployment_commit": "1" * 40,
            "project_name": "eventhorizon-field",
            "platform": "linux/amd64",
            "rendered_config_sha256": "a" * 64,
            "services": services,
            "volumes": [
                "grafana-storage",
                "prometheus-data",
                "tarpit-sock",
            ],
        }
        manifest = {
            "schema_version": 1,
            "run_id": "deploy-20260730T170000Z-a1b2c3",
            "target_alias": "field-host",
            "deployment_commit": "1" * 40,
            "repository_commit": "1" * 40,
            "compose_project_name": "eventhorizon-field",
            "trusted_repository": "honeynet/EventHorizon",
            "approved_branch": "GSoC_2026",
            "starting_state": "INITIAL_DEPLOYMENT",
            "deployed_utc": "2026-07-30T17:00:00Z",
            "platform": "linux/amd64",
            "head_verified": True,
            "worktree_clean": True,
            "docker_version": "27.5.1",
            "compose_version": "2.32.4",
            "rendered_compose_sha256": "a" * 64,
            "pinned_inputs": [
                f"example.invalid/input-{index}:1@sha256:{index}" + "0" * 63
                for index in range(1, 7)
            ],
            "service_image_ids": {
                name: "sha256:" + str(index) * 64
                for index, name in enumerate(port_map, start=1)
            },
            "volume_names": [
                "eventhorizon-field_grafana-storage",
                "eventhorizon-field_prometheus-data",
                "eventhorizon-field_tarpit-sock",
            ],
            "prior_deployment": {
                "commit": None,
                "service_image_ids": {},
                "volume_names": [],
            },
            "cleanup": {
                "attempted": False,
                "succeeded": None,
            },
            "result": "PASS",
        }

        Draft202012Validator(compose_schema).validate(compose_config)
        Draft202012Validator(manifest_schema).validate(manifest)
        with self.assertRaises(ValidationError):
            Draft202012Validator(compose_schema).validate(
                dict(compose_config, unexpected=True)
            )
        with self.assertRaises(ValidationError):
            Draft202012Validator(compose_schema).validate(
                dict(compose_config, deployment_commit="1" * 64)
            )
        with self.assertRaises(ValidationError):
            Draft202012Validator(compose_schema).validate(
                dict(compose_config, rendered_config_sha256="a" * 40)
            )
        with self.assertRaises(ValidationError):
            Draft202012Validator(manifest_schema).validate(
                dict(manifest, schema_version=2)
            )
        inconsistent_cleanup = json.loads(json.dumps(manifest))
        inconsistent_cleanup["result"] = "ERROR"
        inconsistent_cleanup["cleanup"] = {
            "attempted": False,
            "succeeded": True,
        }
        with self.assertRaises(ValidationError):
            Draft202012Validator(manifest_schema).validate(
                inconsistent_cleanup
            )

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

    def test_remote_preflight_schema_is_strict_and_redacted(self) -> None:
        schema = json.loads(
            (
                REPO_ROOT / "deploy/schemas/remote-preflight.schema.json"
            ).read_text(encoding="utf-8")
        )
        evidence = {
            "schema_version": 1,
            "target_alias": "field-host",
            "deployment_commit": "1" * 40,
            "checked_utc": "2026-07-30T01:02:03Z",
            "starting_state": "INITIAL_DEPLOYMENT",
            "result": "PASS",
            "checks": [
                {
                    "id": "operating_system",
                    "status": "PASS",
                    "summary": "Authorized VPS runs Linux.",
                }
            ],
        }
        validator = Draft202012Validator(
            schema,
            format_checker=Draft202012Validator.FORMAT_CHECKER,
        )

        validator.validate(evidence)
        with self.assertRaises(ValidationError):
            validator.validate(dict(evidence, vps_host="198.51.100.10"))
        with self.assertRaises(ValidationError):
            validator.validate(dict(evidence, schema_version=2))

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
        deployment_controller_script = "\n".join(
            step.get("run", "")
            for step in workflow["jobs"]["deployment-controller"]["steps"]
            if isinstance(step, dict)
        )
        self.assertIn(
            "scripts/vps_field_remote_probe.py",
            deployment_controller_script,
        )
        self.assertIn(
            "scripts/vps_field_remote_deploy.py",
            deployment_controller_script,
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
            self.assertIn(
                "AUTHORIZE DEPLOY <full-SHA> TO <target-alias>",
                completed.stdout,
            )
            self.assertIn(
                "Redirected input cannot authorize deployment.",
                completed.stdout,
            )
            self.assertEqual(completed.stderr, "")
            self.assertFalse(output_base.exists())

    def test_internal_remote_preflight_help_is_side_effect_free(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            environment = os.environ.copy()
            environment["VPS_FIELD_ENV_FILE"] = str(
                Path(temporary_directory) / "must-not-be-read.env"
            )

            completed = subprocess.run(
                [
                    str(
                        REPO_ROOT
                        / "scripts/vps_field_remote_preflight.sh"
                    ),
                    "--help",
                ],
                cwd=REPO_ROOT,
                env=environment,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 0)
            self.assertIn(
                "usage: vps_field_remote_preflight.sh",
                completed.stdout,
            )
            self.assertEqual(completed.stderr, "")

    def test_internal_remote_deployment_help_is_side_effect_free(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_path = Path(temporary_directory)

            completed = subprocess.run(
                [
                    sys.executable,
                    str(
                        REPO_ROOT
                        / "scripts/vps_field_remote_deploy.py"
                    ),
                    "--help",
                ],
                cwd=temporary_path,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 0)
            self.assertIn(
                "usage: vps_field_remote_deploy.py <encoded-request>",
                completed.stdout,
            )
            self.assertEqual(completed.stderr, "")
            self.assertEqual(list(temporary_path.iterdir()), [])

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


class RemoteProbeIntegrationTests(unittest.TestCase):
    def test_missing_remote_tools_are_blocked_not_transport_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_path = Path(temporary_directory)
            tools = temporary_path / "tools"
            tools.mkdir()
            dispatcher = tools / "fake-system-tool"
            dispatcher.write_text(
                """#!/usr/bin/python3
import sys
from pathlib import Path

tool = Path(sys.argv[0]).name
if tool == "uname":
    print("Linux" if sys.argv[1:] == ["-s"] else "x86_64")
elif tool == "getconf":
    print("2")
elif tool == "df":
    print("Filesystem 1024-blocks Used Available Capacity Mounted on")
    print("/dev/test 20971520 1024 10485760 1% /")
else:
    raise SystemExit(83)
""",
                encoding="utf-8",
            )
            dispatcher.chmod(0o700)
            for tool_name in ("uname", "getconf", "df"):
                (tools / tool_name).symlink_to(dispatcher)

            request = {
                "schema_version": 1,
                "target_alias": "field-host",
                "deployment_commit": "1" * 40,
                "deploy_dir": str(temporary_path / "eventhorizon-field"),
                "project_name": "eventhorizon-field",
                "trusted_repository": "honeynet/EventHorizon",
                "memory_limit": None,
                "reference_epoch": int(
                    datetime.now(timezone.utc).timestamp()
                ),
            }
            encoded_request = base64.urlsafe_b64encode(
                json.dumps(request).encode("utf-8")
            ).decode("ascii")
            environment = os.environ.copy()
            environment["PATH"] = str(tools)

            completed = subprocess.run(
                [
                    sys.executable,
                    str(REPO_ROOT / "scripts/vps_field_remote_probe.py"),
                    encoded_request,
                ],
                cwd=temporary_path,
                env=environment,
                text=True,
                capture_output=True,
                check=False,
                timeout=10,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            evidence = json.loads(completed.stdout)
            self.assertEqual(evidence["result"], "BLOCKED")
            blockers = {
                check["id"]
                for check in evidence["checks"]
                if check["status"] == "BLOCKER"
            }
            self.assertTrue(
                {
                    "docker_engine",
                    "docker_compose",
                    "git",
                    "curl",
                    "socket_inspection",
                }.issubset(blockers)
            )

    def test_clean_initial_deployment_passes_without_remote_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_path = Path(temporary_directory)
            tools = temporary_path / "tools"
            tools.mkdir()
            dispatcher = tools / "fake-system-tool"
            dispatcher.write_text(
                """#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path

tool = Path(sys.argv[0]).name
arguments = sys.argv[1:]
if tool == "uname":
    print("Linux" if arguments == ["-s"] else "x86_64")
elif tool == "getconf":
    print("2")
elif tool == "docker":
    if arguments == ["info", "--format", "{{.ServerVersion}}"]:
        print("29.5.2")
    elif arguments == ["compose", "version", "--short"]:
        print("5.1.4")
    elif arguments == ["compose", "ls", "--format", "json"]:
        print("[]")
    elif arguments[:3] == ["ps", "-a", "--format"]:
        pass
    elif arguments[:2] == ["volume", "ls"]:
        pass
    else:
        raise SystemExit(81)
elif tool == "git":
    if arguments == ["--version"]:
        print("git version 2.43.0")
    else:
        raise SystemExit(82)
elif tool == "curl":
    print("curl 8.5.0")
elif tool == "ss":
    pass
elif tool == "df":
    print("Filesystem 1024-blocks Used Available Capacity Mounted on")
    print("/dev/test 20971520 1024 10485760 1% /")
else:
    raise SystemExit(83)
""",
                encoding="utf-8",
            )
            dispatcher.chmod(0o700)
            for tool_name in (
                "uname",
                "getconf",
                "docker",
                "git",
                "curl",
                "ss",
                "df",
            ):
                (tools / tool_name).symlink_to(dispatcher)

            request = {
                "schema_version": 1,
                "target_alias": "field-host",
                "deployment_commit": "1" * 40,
                "deploy_dir": str(temporary_path / "eventhorizon-field"),
                "project_name": "eventhorizon-field",
                "trusted_repository": "honeynet/EventHorizon",
                "memory_limit": None,
                "reference_epoch": int(
                    datetime.now(timezone.utc).timestamp()
                ),
            }
            encoded_request = base64.urlsafe_b64encode(
                json.dumps(request).encode("utf-8")
            ).decode("ascii")
            environment = os.environ.copy()
            environment["PATH"] = (
                str(tools) + os.pathsep + environment["PATH"]
            )

            completed = subprocess.run(
                [
                    "python3",
                    str(REPO_ROOT / "scripts/vps_field_remote_probe.py"),
                    encoded_request,
                ],
                cwd=temporary_path,
                env=environment,
                text=True,
                capture_output=True,
                check=False,
                timeout=10,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            evidence = json.loads(completed.stdout)
            self.assertEqual(evidence["result"], "PASS", completed.stdout)
            self.assertEqual(
                evidence["starting_state"],
                "INITIAL_DEPLOYMENT",
            )
            schema = json.loads(
                (
                    REPO_ROOT
                    / "deploy/schemas/remote-preflight.schema.json"
                ).read_text(encoding="utf-8")
            )
            Draft202012Validator(
                schema,
                format_checker=Draft202012Validator.FORMAT_CHECKER,
            ).validate(evidence)
            self.assertFalse((temporary_path / "eventhorizon-field").exists())

            actual_directory = temporary_path / "actual-directory"
            actual_directory.mkdir()
            (temporary_path / "eventhorizon-field").symlink_to(
                actual_directory,
                target_is_directory=True,
            )
            symlinked = subprocess.run(
                [
                    "python3",
                    str(REPO_ROOT / "scripts/vps_field_remote_probe.py"),
                    encoded_request,
                ],
                cwd=temporary_path,
                env=environment,
                text=True,
                capture_output=True,
                check=False,
                timeout=10,
            )
            self.assertEqual(symlinked.returncode, 0, symlinked.stderr)
            symlink_evidence = json.loads(symlinked.stdout)
            self.assertEqual(symlink_evidence["result"], "BLOCKED")
            directory_check = next(
                check
                for check in symlink_evidence["checks"]
                if check["id"] == "deployment_directory"
            )
            self.assertEqual(directory_check["status"], "BLOCKER")

    def test_reconciled_eventhorizon_project_is_managed_redeployment(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_path = Path(temporary_directory)
            deploy_dir = temporary_path / "eventhorizon-field"
            deploy_dir.mkdir()

            def git(*arguments: str) -> str:
                completed = subprocess.run(
                    ["git", *arguments],
                    cwd=deploy_dir,
                    text=True,
                    capture_output=True,
                    check=True,
                )
                return completed.stdout.strip()

            git("init", "-q")
            git("config", "user.name", "Remote Probe Test")
            git("config", "user.email", "probe@example.invalid")
            git(
                "remote",
                "add",
                "origin",
                "git@github.com:honeynet/EventHorizon.git",
            )
            (deploy_dir / ".gitignore").write_text(
                "validation-output/\n",
                encoding="utf-8",
            )
            (deploy_dir / "tracked.txt").write_text(
                "managed checkout\n",
                encoding="utf-8",
            )
            git("add", ".")
            git("commit", "-qm", "managed deployment")
            current_commit = git("rev-parse", "HEAD")
            validation_output = deploy_dir / "validation-output"
            validation_output.mkdir()
            deployment_evidence = (
                validation_output
                / "deployments"
                / "deploy-20260730T160000Z-a1b2c3"
            )
            deployment_evidence.mkdir(parents=True)
            (
                deployment_evidence / "deployment-manifest.json"
            ).write_text(
                json.dumps(
                    {
                        "repository_commit": current_commit,
                        "compose_project_name": "eventhorizon-field",
                        "result": "PASS",
                    }
                ),
                encoding="utf-8",
            )
            (validation_output / "observation_window.json").write_text(
                json.dumps(
                    {
                        "observation_start_utc": "2026-07-18T00:00:00Z",
                        "observation_end_utc": "2026-07-19T00:00:00Z",
                    }
                ),
                encoding="utf-8",
            )

            tools = temporary_path / "tools"
            tools.mkdir()
            dispatcher = tools / "fake-system-tool"
            dispatcher.write_text(
                """#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path

tool = Path(sys.argv[0]).name
arguments = sys.argv[1:]
if tool == "uname":
    print("Linux" if arguments == ["-s"] else "x86_64")
elif tool == "getconf":
    print("2")
elif tool == "df":
    print("Filesystem 1024-blocks Used Available Capacity Mounted on")
    print("/dev/test 20971520 1024 10485760 1% /")
elif tool == "docker":
    if arguments == ["info", "--format", "{{.ServerVersion}}"]:
        print("29.5.2")
    elif arguments == ["compose", "version", "--short"]:
        print("5.1.4")
    elif arguments == ["compose", "ls", "--format", "json"]:
        print(json.dumps([{"Name": "eventhorizon-field"}]))
    elif arguments[:3] == ["ps", "-a", "--format"]:
        rows = [
            ("telnet", "telnet_pit", "0.0.0.0:23->23/tcp"),
            ("mqtt", "mqtt_pit", "0.0.0.0:1883->1883/tcp"),
            ("grafana", "grafana", "127.0.0.1:3000->3000/tcp"),
            ("cadvisor", "cadvisor", "127.0.0.1:8081->8081/tcp"),
            ("prometheus", "prometheus", "127.0.0.1:9090->9090/tcp"),
            (
                "exporter",
                "prometheus-exporter",
                "127.0.0.1:9101->9101/tcp",
            ),
        ]
        missing = os.environ.get("FAKE_MISSING_SERVICE")
        for name, service, ports in rows:
            if service != missing:
                print(
                    f"{name}\\teventhorizon-field\\t{service}\\t{ports}"
                )
    elif arguments[:2] == ["volume", "ls"]:
        print("eventhorizon-field_prometheus-data")
        print("eventhorizon-field_grafana-storage")
        print("eventhorizon-field_tarpit-sock")
        if os.environ.get("FAKE_EXTRA_VOLUME") == "1":
            print("eventhorizon-field_unmanaged-data")
    else:
        raise SystemExit(81)
elif tool == "curl":
    print("curl 8.5.0")
elif tool == "ss":
    if arguments != ["--version"]:
        for port in (23, 1883, 3000, 8081, 9090, 9101):
            missing_port = {
                "telnet_pit": 23,
                "mqtt_pit": 1883,
                "grafana": 3000,
                "cadvisor": 8081,
                "prometheus": 9090,
                "prometheus-exporter": 9101,
            }.get(os.environ.get("FAKE_MISSING_SERVICE"))
            if port != missing_port:
                print(f"LISTEN 0 4096 127.0.0.1:{port} 0.0.0.0:*")
else:
    raise SystemExit(83)
""",
                encoding="utf-8",
            )
            dispatcher.chmod(0o700)
            for tool_name in (
                "uname",
                "getconf",
                "docker",
                "curl",
                "ss",
                "df",
            ):
                (tools / tool_name).symlink_to(dispatcher)

            request = {
                "schema_version": 1,
                "target_alias": "field-host",
                "deployment_commit": "1" * 40,
                "deploy_dir": str(deploy_dir),
                "project_name": "eventhorizon-field",
                "trusted_repository": "honeynet/EventHorizon",
                "memory_limit": None,
                "reference_epoch": int(
                    datetime.now(timezone.utc).timestamp()
                ),
            }
            encoded_request = base64.urlsafe_b64encode(
                json.dumps(request).encode("utf-8")
            ).decode("ascii")
            environment = os.environ.copy()
            environment["PATH"] = (
                str(tools) + os.pathsep + environment["PATH"]
            )

            completed = subprocess.run(
                [
                    "python3",
                    str(REPO_ROOT / "scripts/vps_field_remote_probe.py"),
                    encoded_request,
                ],
                cwd=temporary_path,
                env=environment,
                text=True,
                capture_output=True,
                check=False,
                timeout=10,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            evidence = json.loads(completed.stdout)
            self.assertEqual(evidence["result"], "PASS", completed.stdout)
            self.assertEqual(
                evidence["starting_state"],
                "MANAGED_REDEPLOYMENT",
            )
            self.assertEqual(git("rev-parse", "HEAD"), current_commit)
            self.assertEqual(git("status", "--porcelain"), "")

            environment["FAKE_MISSING_SERVICE"] = "telnet_pit"
            missing_service = subprocess.run(
                [
                    "python3",
                    str(REPO_ROOT / "scripts/vps_field_remote_probe.py"),
                    encoded_request,
                ],
                cwd=temporary_path,
                env=environment,
                text=True,
                capture_output=True,
                check=False,
                timeout=10,
            )
            self.assertEqual(
                missing_service.returncode,
                0,
                missing_service.stderr,
            )
            missing_service_evidence = json.loads(
                missing_service.stdout
            )
            self.assertEqual(
                missing_service_evidence["result"],
                "BLOCKED",
            )
            service_check = next(
                check
                for check in missing_service_evidence["checks"]
                if check["id"] == "container_state"
            )
            self.assertEqual(service_check["status"], "BLOCKER")
            del environment["FAKE_MISSING_SERVICE"]

            (validation_output / "observation_window.json").write_text(
                json.dumps(
                    {
                        "observation_start_utc": "2026-07-30T01:00:00Z",
                    }
                ),
                encoding="utf-8",
            )
            blocked = subprocess.run(
                [
                    "python3",
                    str(REPO_ROOT / "scripts/vps_field_remote_probe.py"),
                    encoded_request,
                ],
                cwd=temporary_path,
                env=environment,
                text=True,
                capture_output=True,
                check=False,
                timeout=10,
            )
            self.assertEqual(blocked.returncode, 0, blocked.stderr)
            blocked_evidence = json.loads(blocked.stdout)
            self.assertEqual(blocked_evidence["result"], "BLOCKED")
            observation_check = next(
                check
                for check in blocked_evidence["checks"]
                if check["id"] == "public_observation"
            )
            self.assertEqual(observation_check["status"], "BLOCKER")

            (validation_output / "observation_window.json").write_text(
                json.dumps(
                    {
                        "observation_start_utc": "2026-07-18T00:00:00Z",
                        "observation_end_utc": "2026-07-19T00:00:00Z",
                    }
                ),
                encoding="utf-8",
            )
            environment["FAKE_EXTRA_VOLUME"] = "1"
            extra_volume = subprocess.run(
                [
                    "python3",
                    str(REPO_ROOT / "scripts/vps_field_remote_probe.py"),
                    encoded_request,
                ],
                cwd=temporary_path,
                env=environment,
                text=True,
                capture_output=True,
                check=False,
                timeout=10,
            )
            self.assertEqual(extra_volume.returncode, 0, extra_volume.stderr)
            volume_evidence = json.loads(extra_volume.stdout)
            self.assertEqual(volume_evidence["result"], "BLOCKED")
            volume_check = next(
                check
                for check in volume_evidence["checks"]
                if check["id"] == "volume_state"
            )
            self.assertEqual(volume_check["status"], "BLOCKER")


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


class RemoteDeploymentProgramIntegrationTests(unittest.TestCase):
    def test_failed_initial_clone_does_not_strand_deployment_directory(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_path = Path(temporary_directory)
            fake_bin = temporary_path / "fake-bin"
            fake_bin.mkdir()
            fake_git = fake_bin / "git"
            fake_git.write_text(
                """#!/usr/bin/env python3
from pathlib import Path
import sys

if sys.argv[1] != "clone":
    raise SystemExit(91)
target = Path(sys.argv[-1])
target.mkdir(parents=True, exist_ok=True)
(target / "partial-clone").write_text("incomplete\\n")
raise SystemExit(92)
""",
                encoding="utf-8",
            )
            fake_git.chmod(0o700)
            deploy_dir = (
                temporary_path
                / "authorized"
                / "vps"
                / "eventhorizon-field"
            )
            request = {
                "schema_version": 1,
                "run_id": "deploy-20260730T165900Z-a1b2c3",
                "target_alias": "field-host",
                "deployment_commit": "1" * 40,
                "deploy_dir": str(deploy_dir),
                "project_name": "eventhorizon-field",
                "trusted_repository": "honeynet/EventHorizon",
                "approved_branch": "GSoC_2026",
                "starting_state": "INITIAL_DEPLOYMENT",
                "compose_files": [
                    "docker-compose.yml",
                    "docker-compose.cost.yml",
                    "docker-compose.field.yml",
                ],
                "cpu_limit": "0.50",
                "memory_limit": None,
            }
            environment = os.environ.copy()
            environment["PATH"] = (
                str(fake_bin) + os.pathsep + environment["PATH"]
            )

            completed = subprocess.run(
                [
                    sys.executable,
                    str(
                        REPO_ROOT
                        / "scripts/vps_field_remote_deploy.py"
                    ),
                    base64.urlsafe_b64encode(
                        json.dumps(request).encode("utf-8")
                    ).decode("ascii"),
                ],
                text=True,
                capture_output=True,
                check=False,
                env=environment,
                timeout=10,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            response = json.loads(completed.stdout)
            self.assertEqual(response["result"], "ERROR")
            self.assertTrue(response["remote_mutation_occurred"])
            self.assertFalse(response["field_services_running"])
            self.assertFalse(deploy_dir.exists())
            self.assertEqual(list(deploy_dir.parent.iterdir()), [])

            deploy_dir.mkdir()
            marker = deploy_dir / "operator-owned-file"
            marker.write_text("must remain untouched\n", encoding="utf-8")
            blocked_request = dict(
                request,
                run_id="deploy-20260730T165901Z-d4e5f6",
            )
            blocked = subprocess.run(
                [
                    sys.executable,
                    str(
                        REPO_ROOT
                        / "scripts/vps_field_remote_deploy.py"
                    ),
                    base64.urlsafe_b64encode(
                        json.dumps(blocked_request).encode("utf-8")
                    ).decode("ascii"),
                ],
                text=True,
                capture_output=True,
                check=False,
                env=environment,
                timeout=10,
            )
            self.assertEqual(blocked.returncode, 0, blocked.stderr)
            blocked_response = json.loads(blocked.stdout)
            self.assertEqual(blocked_response["result"], "BLOCKED")
            self.assertFalse(
                blocked_response["remote_mutation_occurred"]
            )
            self.assertEqual(
                marker.read_text(encoding="utf-8"),
                "must remain untouched\n",
            )

    def test_initial_deployment_checks_out_an_exact_ancestor_and_starts_stack(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_path = Path(temporary_directory)
            source = temporary_path / "source"
            upstream = temporary_path / "upstream.git"
            source.mkdir()

            def git(*arguments: str, cwd: Path = source) -> str:
                return subprocess.run(
                    ["git", *arguments],
                    cwd=cwd,
                    text=True,
                    capture_output=True,
                    check=True,
                ).stdout.strip()

            git("init", "-q", "-b", "GSoC_2026")
            git("config", "user.name", "Deployment Test")
            git("config", "user.email", "deployment@example.invalid")
            (source / "deploy").mkdir()
            shutil.copy2(
                REPO_ROOT / "deploy/deployment-policy.json",
                source / "deploy/deployment-policy.json",
            )
            for compose_file in (
                "docker-compose.yml",
                "docker-compose.cost.yml",
                "docker-compose.field.yml",
            ):
                (source / compose_file).write_text(
                    "services: {}\n",
                    encoding="utf-8",
                )
            (source / ".env").write_text(
                "TELNET_PORT=23\nMQTT_PORT=1883\n",
                encoding="utf-8",
            )
            (source / ".gitignore").write_text(
                "validation-output/\n",
                encoding="utf-8",
            )
            git("add", ".")
            git("commit", "-qm", "deployable ancestor")
            deployment_commit = git("rev-parse", "HEAD")
            (source / "later.txt").write_text(
                "branch tip may advance\n",
                encoding="utf-8",
            )
            git("add", "later.txt")
            git("commit", "-qm", "later branch tip")
            git("init", "--bare", "-q", str(upstream))
            git("remote", "add", "origin", str(upstream))
            git("push", "-q", "origin", "GSoC_2026")

            deploy_dir = (
                temporary_path
                / "authorized"
                / "vps"
                / "eventhorizon-field"
            )
            fixture_policy = json.loads(
                (source / "deploy/deployment-policy.json").read_text(
                    encoding="utf-8"
                )
            )
            compose_images = fixture_policy["field_build"]["compose_images"]
            rendered_config = {
                "name": "eventhorizon-field",
                "services": {
                    "prometheus-exporter": {
                        "build": {
                            "context": str(deploy_dir),
                            "dockerfile": "./docker/prometheus/Dockerfile",
                        },
                        "platform": "linux/amd64",
                        "ports": [
                            {
                                "host_ip": "127.0.0.1",
                                "published": "9101",
                                "target": 9101,
                                "protocol": "tcp",
                            }
                        ],
                        "restart": "unless-stopped",
                        "logging": {"driver": "json-file"},
                        "volumes": [
                            {
                                "type": "bind",
                                "source": str(deploy_dir / "private"),
                                "target": "/data/GeoLite2-Country.mmdb",
                                "read_only": True,
                            }
                        ],
                    },
                    "telnet_pit": {
                        "build": {
                            "context": str(deploy_dir),
                            "dockerfile": "./docker/tarpits/Dockerfile",
                        },
                        "platform": "linux/amd64",
                        "ports": [
                            {
                                "host_ip": "0.0.0.0",
                                "published": "23",
                                "target": 23,
                                "protocol": "tcp",
                            }
                        ],
                        "restart": "unless-stopped",
                        "logging": {"driver": "none"},
                        "cpus": 0.5,
                        "mem_limit": "268435456",
                    },
                    "mqtt_pit": {
                        "build": {
                            "context": str(deploy_dir),
                            "dockerfile": "./docker/tarpits/Dockerfile",
                        },
                        "platform": "linux/amd64",
                        "ports": [
                            {
                                "host_ip": "0.0.0.0",
                                "published": "1883",
                                "target": 1883,
                                "protocol": "tcp",
                            }
                        ],
                        "restart": "unless-stopped",
                        "logging": {"driver": "none"},
                        "cpus": 0.5,
                        "mem_limit": "268435456",
                    },
                    "prometheus": {
                        "image": compose_images["prometheus"],
                        "platform": "linux/amd64",
                        "ports": [
                            {
                                "host_ip": "127.0.0.1",
                                "published": "9090",
                                "target": 9090,
                                "protocol": "tcp",
                            }
                        ],
                        "restart": "unless-stopped",
                        "logging": {"driver": "json-file"},
                    },
                    "grafana": {
                        "image": compose_images["grafana"],
                        "platform": "linux/amd64",
                        "ports": [
                            {
                                "host_ip": "127.0.0.1",
                                "published": "3000",
                                "target": 3000,
                                "protocol": "tcp",
                            }
                        ],
                        "restart": "unless-stopped",
                        "logging": {"driver": "json-file"},
                    },
                    "cadvisor": {
                        "image": compose_images["cadvisor"],
                        "platform": "linux/amd64",
                        "privileged": True,
                        "ports": [
                            {
                                "host_ip": "127.0.0.1",
                                "published": "8081",
                                "target": 8080,
                                "protocol": "tcp",
                            }
                        ],
                        "restart": "unless-stopped",
                        "logging": {"driver": "json-file"},
                    },
                },
                "volumes": {
                    "grafana-storage": {},
                    "prometheus-data": {},
                    "tarpit-sock": {},
                },
            }
            rendered_path = temporary_path / "rendered-compose.json"
            rendered_path.write_text(
                json.dumps(rendered_config),
                encoding="utf-8",
            )
            fake_bin = temporary_path / "fake-bin"
            fake_bin.mkdir()
            fake_docker = fake_bin / "docker"
            fake_docker.write_text(
                """#!/usr/bin/env python3
import hashlib
import os
from pathlib import Path
import sys

arguments = sys.argv[1:]
if arguments[:2] == ["compose", "version"]:
    print("2.32.4")
elif arguments and arguments[0] == "compose" and "config" in arguments:
    print(Path(os.environ["FAKE_RENDERED_CONFIG"]).read_text())
elif arguments and arguments[0] == "compose" and "up" in arguments:
    Path(os.environ["FAKE_STACK_STATE"]).write_text("running\\n")
    if os.environ.get("FAKE_FAIL_AFTER_START") == "yes":
        raise SystemExit(88)
elif arguments and arguments[0] == "compose" and "stop" in arguments:
    Path(os.environ["FAKE_STACK_STATE"]).write_text("stopped\\n")
elif arguments and arguments[0] == "compose" and "ps" in arguments:
    state_path = Path(os.environ["FAKE_STACK_STATE"])
    state = state_path.read_text().strip() if state_path.exists() else "absent"
    service = arguments[-1]
    if (
        service != os.environ.get("FAKE_MISSING_CONTAINER")
        and (state != "stopped" or "--all" in arguments)
    ):
        print("container-" + arguments[-1])
elif arguments and arguments[0] == "inspect":
    print("sha256:" + hashlib.sha256(arguments[-1].encode()).hexdigest())
elif arguments[:2] == ["volume", "ls"]:
    print("eventhorizon-field_grafana-storage")
    print("eventhorizon-field_prometheus-data")
    print("eventhorizon-field_tarpit-sock")
elif arguments and arguments[0] == "version":
    print("27.5.1")
else:
    raise SystemExit(90)
""",
                encoding="utf-8",
            )
            fake_docker.chmod(0o700)

            run_id = "deploy-20260730T170000Z-a1b2c3"
            request = {
                "schema_version": 1,
                "run_id": run_id,
                "target_alias": "field-host",
                "deployment_commit": deployment_commit,
                "deploy_dir": str(deploy_dir),
                "project_name": "eventhorizon-field",
                "trusted_repository": "honeynet/EventHorizon",
                "approved_branch": "GSoC_2026",
                "starting_state": "INITIAL_DEPLOYMENT",
                "compose_files": [
                    "docker-compose.yml",
                    "docker-compose.cost.yml",
                    "docker-compose.field.yml",
                ],
                "cpu_limit": "0.50",
                "memory_limit": "256m",
            }
            encoded_request = base64.urlsafe_b64encode(
                json.dumps(request).encode("utf-8")
            ).decode("ascii")
            stack_state = temporary_path / "stack-state"
            environment = os.environ.copy()
            environment.update(
                {
                    "PATH": f"{fake_bin}:{environment['PATH']}",
                    "FAKE_RENDERED_CONFIG": str(rendered_path),
                    "FAKE_STACK_STATE": str(stack_state),
                    "GIT_CONFIG_COUNT": "1",
                    "GIT_CONFIG_KEY_0": (
                        f"url.{upstream.resolve().as_uri()}.insteadOf"
                    ),
                    "GIT_CONFIG_VALUE_0": (
                        "https://github.com/honeynet/EventHorizon.git"
                    ),
                }
            )

            completed = subprocess.run(
                [
                    sys.executable,
                    str(REPO_ROOT / "scripts/vps_field_remote_deploy.py"),
                    encoded_request,
                ],
                text=True,
                capture_output=True,
                check=False,
                env=environment,
                timeout=30,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            response = json.loads(completed.stdout)
            self.assertEqual(response["result"], "PASS", response)
            self.assertTrue(response["remote_mutation_occurred"])
            self.assertTrue(response["field_services_running"])

            class CapturedDeploymentTransport:
                def __init__(self, payload: str) -> None:
                    self.payload = payload

                def execute(
                    self,
                    configuration,
                    commit,
                    policy,
                    preflight,
                    requested_run_id,
                ) -> RemoteDeploymentExecution:
                    return RemoteDeploymentExecution(
                        returncode=0,
                        stdout=self.payload.encode("utf-8"),
                        stderr=b"",
                    )

            target_configuration = TargetConfiguration(
                target_alias="field-host",
                vps_host="example.invalid",
                vps_user="deploy",
                vps_ssh_port=22,
                vps_ssh_key=temporary_path / "unused-test-key",
                vps_deploy_dir=str(deploy_dir),
                vps_project_name="eventhorizon-field",
                admin_source_cidr="192.0.2.1/32",
                field_tarpit_cpu_limit="0.50",
                field_tarpit_memory_limit="256m",
            )
            workstation_verification = SshExactSourceDeployment(
                CapturedDeploymentTransport(completed.stdout)
            ).deploy(
                target_configuration,
                deployment_commit,
                fixture_policy,
                {"starting_state": "INITIAL_DEPLOYMENT"},
                run_id,
            )
            self.assertTrue(
                workstation_verification.passed,
                json.dumps(response, indent=2, sort_keys=True),
            )
            self.assertEqual(
                git("-C", str(deploy_dir), "rev-parse", "HEAD"),
                deployment_commit,
            )
            self.assertEqual(
                git(
                    "-C",
                    str(deploy_dir),
                    "status",
                    "--porcelain",
                    "--untracked-files=normal",
                ),
                "",
            )
            self.assertEqual(stack_state.read_text(), "running\n")
            run_directory = (
                deploy_dir / "validation-output" / "deployments" / run_id
            )
            collected_documents = {}
            for artifact_name in (
                "compose-config.json",
                "deployment-manifest.json",
            ):
                artifact = run_directory / artifact_name
                self.assertTrue(artifact.is_file())
                self.assertEqual(stat.S_IMODE(artifact.stat().st_mode), 0o600)
                collected_documents[artifact_name] = json.loads(
                    artifact.read_text(encoding="utf-8")
                )
            Draft202012Validator(
                json.loads(
                    (
                        REPO_ROOT
                        / "deploy/schemas/compose-config.schema.json"
                    ).read_text(encoding="utf-8")
                )
            ).validate(collected_documents["compose-config.json"])
            Draft202012Validator(
                json.loads(
                    (
                        REPO_ROOT
                        / "deploy/schemas/deployment-manifest.schema.json"
                    ).read_text(encoding="utf-8")
                )
            ).validate(collected_documents["deployment-manifest.json"])
            self.assertEqual(
                response["compose_config"],
                collected_documents["compose-config.json"],
            )
            self.assertEqual(
                response["deployment_manifest"],
                collected_documents["deployment-manifest.json"],
            )
            retained = json.dumps(response)
            self.assertNotIn(str(source), retained)
            self.assertNotIn(str(deploy_dir), retained)

            git(
                "-C",
                str(deploy_dir),
                "remote",
                "set-url",
                "origin",
                "https://github.com/honeynet/EventHorizon.git",
            )
            failed_run_id = "deploy-20260730T170100Z-d4e5f6"
            failed_request = dict(
                request,
                run_id=failed_run_id,
                deployment_commit=git("rev-parse", "HEAD"),
                starting_state="MANAGED_REDEPLOYMENT",
            )
            failed_environment = dict(
                environment,
                FAKE_FAIL_AFTER_START="yes",
            )
            failed = subprocess.run(
                [
                    sys.executable,
                    str(REPO_ROOT / "scripts/vps_field_remote_deploy.py"),
                    base64.urlsafe_b64encode(
                        json.dumps(failed_request).encode("utf-8")
                    ).decode("ascii"),
                ],
                text=True,
                capture_output=True,
                check=False,
                env=failed_environment,
                timeout=30,
            )

            self.assertEqual(failed.returncode, 0, failed.stderr)
            failed_response = json.loads(failed.stdout)
            self.assertEqual(
                failed_response["result"],
                "ERROR",
                failed_response,
            )
            self.assertTrue(failed_response["remote_mutation_occurred"])
            self.assertFalse(failed_response["field_services_running"])
            self.assertEqual(stack_state.read_text(), "stopped\n")
            self.assertEqual(
                failed_response["deployment_manifest"]["cleanup"],
                {"attempted": True, "succeeded": True},
            )
            failed_run_directory = (
                deploy_dir
                / "validation-output"
                / "deployments"
                / failed_run_id
            )
            self.assertTrue(
                (failed_run_directory / "compose-config.json").is_file()
            )
            self.assertTrue(
                (failed_run_directory / "deployment-manifest.json").is_file()
            )
            failed_manifest = json.loads(
                (
                    failed_run_directory / "deployment-manifest.json"
                ).read_text(encoding="utf-8")
            )
            Draft202012Validator(
                json.loads(
                    (
                        REPO_ROOT
                        / "deploy/schemas/deployment-manifest.schema.json"
                    ).read_text(encoding="utf-8")
                )
            ).validate(failed_manifest)
            self.assertEqual(
                failed_manifest["prior_deployment"]["commit"],
                deployment_commit,
            )
            failed_workstation_verification = SshExactSourceDeployment(
                CapturedDeploymentTransport(failed.stdout)
            ).deploy(
                target_configuration,
                failed_request["deployment_commit"],
                fixture_policy,
                {"starting_state": "MANAGED_REDEPLOYMENT"},
                failed_run_id,
            )
            self.assertFalse(failed_workstation_verification.passed)
            self.assertEqual(
                failed_workstation_verification.outcome,
                "ERROR",
            )
            self.assertTrue(
                failed_workstation_verification.remote_mutation_occurred
            )
            self.assertFalse(
                failed_workstation_verification.field_services_running,
                json.dumps(
                    failed_response,
                    indent=2,
                    sort_keys=True,
                ),
            )

            recovery_run_id = "deploy-20260730T170200Z-g7h8i9"
            recovery_request = dict(
                failed_request,
                run_id=recovery_run_id,
            )
            recovered = subprocess.run(
                [
                    sys.executable,
                    str(REPO_ROOT / "scripts/vps_field_remote_deploy.py"),
                    base64.urlsafe_b64encode(
                        json.dumps(recovery_request).encode("utf-8")
                    ).decode("ascii"),
                ],
                text=True,
                capture_output=True,
                check=False,
                env=environment,
                timeout=30,
            )

            self.assertEqual(recovered.returncode, 0, recovered.stderr)
            recovered_response = json.loads(recovered.stdout)
            self.assertEqual(
                recovered_response["result"],
                "PASS",
                recovered_response,
            )
            self.assertTrue(
                recovered_response["field_services_running"]
            )
            self.assertEqual(stack_state.read_text(), "running\n")

            missing_run_id = "deploy-20260730T170300Z-j1k2l3"
            missing_request = dict(
                recovery_request,
                run_id=missing_run_id,
            )
            missing_environment = dict(
                environment,
                FAKE_MISSING_CONTAINER="cadvisor",
            )
            missing = subprocess.run(
                [
                    sys.executable,
                    str(REPO_ROOT / "scripts/vps_field_remote_deploy.py"),
                    base64.urlsafe_b64encode(
                        json.dumps(missing_request).encode("utf-8")
                    ).decode("ascii"),
                ],
                text=True,
                capture_output=True,
                check=False,
                env=missing_environment,
                timeout=30,
            )

            self.assertEqual(missing.returncode, 0, missing.stderr)
            missing_response = json.loads(missing.stdout)
            self.assertEqual(
                missing_response["result"],
                "BLOCKED",
                missing_response,
            )
            self.assertEqual(
                missing_response["blocker"],
                (
                    "Managed deployment no longer contains every "
                    "evidenced field service."
                ),
            )


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
                "starting_state": "INITIAL_DEPLOYMENT",
                "result": "PASS",
            },
            blocker=None,
        )


class InitialDeploymentProbe:
    def collect(
        self,
        configuration: object,
        commit: str,
        policy: dict[str, object],
    ) -> RemoteProbeExecution:
        return RemoteProbeExecution(
            returncode=0,
            stdout=json.dumps(
                {
                    "schema_version": 1,
                    "target_alias": "field-host",
                    "deployment_commit": commit,
                    "checked_utc": "2026-07-30T01:02:03Z",
                    "starting_state": "INITIAL_DEPLOYMENT",
                    "result": "PASS",
                    "checks": [
                        {
                            "id": "operating_system",
                            "status": "PASS",
                            "summary": "Authorized VPS runs Linux.",
                        }
                    ],
                }
            ).encode("utf-8"),
            stderr=b"",
        )


class MalfunctioningRemoteProbe:
    def collect(
        self,
        configuration: object,
        commit: str,
        policy: dict[str, object],
    ) -> RemoteProbeExecution:
        return RemoteProbeExecution(
            returncode=255,
            stdout=b"",
            stderr=b"ssh: sensitive transport diagnostic",
        )


class PrivacyExpandingRemoteProbe:
    def collect(
        self,
        configuration: object,
        commit: str,
        policy: dict[str, object],
    ) -> RemoteProbeExecution:
        return RemoteProbeExecution(
            returncode=0,
            stdout=json.dumps(
                {
                    "schema_version": 1,
                    "target_alias": "field-host",
                    "deployment_commit": commit,
                    "checked_utc": "2026-07-30T01:02:03Z",
                    "starting_state": "INITIAL_DEPLOYMENT",
                    "result": "PASS",
                    "checks": [
                        {
                            "id": "operating_system",
                            "status": "PASS",
                            "summary": "Authorized VPS runs Linux.",
                        }
                    ],
                    "vps_host": "198.51.100.10",
                }
            ).encode("utf-8"),
            stderr=b"",
        )


class PrivacyExpandingDeploymentTransport:
    def execute(
        self,
        configuration: object,
        commit: str,
        policy: dict[str, object],
        preflight: dict[str, object],
        run_id: str,
    ) -> RemoteDeploymentExecution:
        return RemoteDeploymentExecution(
            returncode=0,
            stdout=json.dumps(
                {
                    "schema_version": 1,
                    "run_id": run_id,
                    "target_alias": "field-host",
                    "deployment_commit": commit,
                    "result": "PASS",
                    "blocker": None,
                    "remote_mutation_occurred": True,
                    "field_services_running": True,
                    "compose_config": {
                        "schema_version": 1,
                        "deployment_commit": commit,
                        "vps_host": "198.51.100.10",
                    },
                    "deployment_manifest": {
                        "schema_version": 1,
                        "run_id": run_id,
                        "deployment_commit": commit,
                        "result": "PASS",
                    },
                }
            ).encode("utf-8"),
            stderr=b"",
        )


class DeclinedAuthorization:
    def authorize(self, phrase: str) -> AuthorizationDecision:
        return AuthorizationDecision(authorized=False)


class ApprovedAuthorization:
    def authorize(self, phrase: str) -> AuthorizationDecision:
        return AuthorizationDecision(authorized=True)


class InterruptedAuthorization:
    def authorize(self, phrase: str) -> AuthorizationDecision:
        raise KeyboardInterrupt


class InteractiveTextStream(io.StringIO):
    def isatty(self) -> bool:
        return True


class DeploymentControllerApiTests(unittest.TestCase):
    def test_evidence_write_failure_preserves_proven_remote_state(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_path = Path(temporary_directory)
            target_file, _ = write_strict_target_configuration(
                temporary_path
            )
            output_directory = temporary_path / "evidence"

            class WriteBreakingDeployment:
                def deploy(
                    self,
                    configuration: object,
                    deployment_commit: str,
                    policy: dict[str, object],
                    preflight: dict[str, object],
                    run_id: str,
                ) -> RemoteDeploymentVerification:
                    run_directory = (
                        output_directory / "deployments" / run_id
                    )
                    run_directory.chmod(0o500)
                    return RemoteDeploymentVerification(
                        passed=True,
                        outcome="PASS",
                        blocker=None,
                        remote_mutation_occurred=True,
                        field_services_running=True,
                        compose_config={},
                        deployment_manifest={},
                    )

            try:
                with self.assertRaises(EvidenceError) as caught:
                    run(
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
                            remote=ReadyRemote(),
                            authorization=ApprovedAuthorization(),
                            deployment=WriteBreakingDeployment(),
                        ),
                    )
                self.assertIsNotNone(caught.exception.result)
                self.assertTrue(
                    caught.exception.result.remote_mutation_occurred
                )
                self.assertTrue(
                    caught.exception.result.field_services_running
                )
                self.assertEqual(
                    caught.exception.result.highest_state,
                    "CI_VALIDATED",
                )
            finally:
                deployments = output_directory / "deployments"
                if deployments.is_dir():
                    for run_directory in deployments.iterdir():
                        run_directory.chmod(0o700)

    def test_successful_exact_source_deployment_advances_to_runtime_verification(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_path = Path(temporary_directory)
            target_file, _ = write_strict_target_configuration(temporary_path)
            output_directory = temporary_path / "evidence"
            commit = "1" * 40

            class ReadyDeployment:
                def deploy(
                    self,
                    configuration: object,
                    deployment_commit: str,
                    policy: dict[str, object],
                    preflight: dict[str, object],
                    run_id: str,
                ) -> RemoteDeploymentVerification:
                    return RemoteDeploymentVerification(
                        passed=True,
                        outcome="PASS",
                        blocker=None,
                        remote_mutation_occurred=True,
                        field_services_running=True,
                        compose_config={
                            "schema_version": 1,
                            "deployment_commit": deployment_commit,
                        },
                        deployment_manifest={
                            "schema_version": 1,
                            "run_id": run_id,
                            "deployment_commit": deployment_commit,
                            "result": "PASS",
                        },
                    )

            result = run(
                DeploymentRequest(
                    check_only=False,
                    commit=commit,
                    env_file=target_file,
                    output_dir=output_directory,
                ),
                ControllerAdapters(
                    clock=FixedClock(),
                    randomness=FixedRandomSource(),
                    repository=ProvenRepository(),
                    trusted_ci=ProvenTrustedCi(),
                    remote=ReadyRemote(),
                    authorization=ApprovedAuthorization(),
                    deployment=ReadyDeployment(),
                ),
            )

            checks = {check.check_id: check for check in result.checks}
            self.assertEqual(checks["exact_source_deployment"].status, "PASS")
            self.assertEqual(
                checks["runtime_verification_foundation"].status,
                "BLOCKER",
            )
            self.assertTrue(result.remote_mutation_occurred)
            self.assertTrue(result.field_services_running)
            self.assertEqual(result.highest_state, "CI_VALIDATED")
            self.assertEqual(result.outcome, "BLOCKED")

            run_directory = (
                output_directory / "deployments" / result.run_id
            )
            self.assertEqual(
                json.loads(
                    (run_directory / "compose-config.json").read_text(
                        encoding="utf-8"
                    )
                )["deployment_commit"],
                commit,
            )
            self.assertEqual(
                json.loads(
                    (run_directory / "deployment-manifest.json").read_text(
                        encoding="utf-8"
                    )
                )["result"],
                "PASS",
            )

    def test_production_authorization_accepts_the_exact_tty_phrase(self) -> None:
        phrase = (
            "AUTHORIZE DEPLOY "
            "1111111111111111111111111111111111111111 TO field-host"
        )
        authorization_input = InteractiveTextStream(phrase + "\n")
        prompt_output = InteractiveTextStream()

        adapters = production_adapters(
            authorization_input=authorization_input,
            prompt_output=prompt_output,
        )

        self.assertIsNotNone(adapters.authorization)
        decision = adapters.authorization.authorize(phrase)
        self.assertTrue(decision.authorized)
        self.assertIn(phrase, prompt_output.getvalue())

    def test_production_authorization_explains_the_attestation(self) -> None:
        phrase = (
            "AUTHORIZE DEPLOY "
            "1111111111111111111111111111111111111111 TO field-host"
        )
        authorization_input = InteractiveTextStream(phrase + "\n")
        prompt_output = InteractiveTextStream()

        adapters = production_adapters(
            authorization_input=authorization_input,
            prompt_output=prompt_output,
        )
        self.assertIsNotNone(adapters.authorization)
        adapters.authorization.authorize(phrase)

        prompt = prompt_output.getvalue()
        self.assertIn("target is authorized", prompt)
        self.assertIn("firewall policy was reviewed", prompt)
        self.assertIn("management access is source-restricted", prompt)

    def test_production_authorization_rejects_a_near_match(self) -> None:
        phrase = (
            "AUTHORIZE DEPLOY "
            "1111111111111111111111111111111111111111 TO field-host"
        )
        authorization_input = InteractiveTextStream(phrase + " \n")

        adapters = production_adapters(
            authorization_input=authorization_input,
            prompt_output=InteractiveTextStream(),
        )

        self.assertIsNotNone(adapters.authorization)
        decision = adapters.authorization.authorize(phrase)
        self.assertFalse(decision.authorized)

    def test_production_authorization_rejects_non_tty_input(self) -> None:
        phrase = (
            "AUTHORIZE DEPLOY "
            "1111111111111111111111111111111111111111 TO field-host"
        )
        redirected_input = io.StringIO(phrase + "\n")

        adapters = production_adapters(
            authorization_input=redirected_input,
            prompt_output=InteractiveTextStream(),
        )

        self.assertIsNone(adapters.authorization)

    def test_exact_production_authorization_advances_to_phase_six(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_path = Path(temporary_directory)
            target_file, _ = write_strict_target_configuration(temporary_path)
            output_directory = temporary_path / "evidence"
            commit = "1" * 40
            phrase = f"AUTHORIZE DEPLOY {commit} TO field-host"
            production = production_adapters(
                authorization_input=InteractiveTextStream(phrase + "\n"),
                prompt_output=InteractiveTextStream(),
            )
            self.assertIsNotNone(production.authorization)

            result = run(
                DeploymentRequest(
                    check_only=False,
                    commit=commit,
                    env_file=target_file,
                    output_dir=output_directory,
                ),
                ControllerAdapters(
                    clock=FixedClock(),
                    randomness=FixedRandomSource(),
                    repository=ProvenRepository(),
                    trusted_ci=ProvenTrustedCi(),
                    remote=ReadyRemote(),
                    authorization=production.authorization,
                ),
            )

            self.assertEqual(result.outcome, "BLOCKED")
            self.assertEqual(result.highest_state, "CI_VALIDATED")
            self.assertFalse(result.remote_mutation_occurred)
            checks = {check.check_id: check for check in result.checks}
            self.assertEqual(checks["authorization"].status, "PASS")
            self.assertEqual(
                checks["exact_source_deployment_foundation"].status,
                "BLOCKER",
            )
            authorization = json.loads(
                (
                    output_directory
                    / "deployments"
                    / result.run_id
                    / "authorization.json"
                ).read_text(encoding="utf-8")
            )
            self.assertTrue(authorization["authorization_attested"])
            self.assertEqual(authorization["result"], "PASS")

    def test_production_adapters_include_remote_preflight_capability(
        self,
    ) -> None:
        adapters = production_adapters()

        self.assertIsNotNone(adapters.repository)
        self.assertIsNotNone(adapters.trusted_ci)
        self.assertIsNotNone(adapters.remote)
        self.assertIsNotNone(adapters.deployment)

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
            target_file, ssh_key = write_strict_target_configuration(
                temporary_path
            )
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

    def test_initial_remote_preflight_passes_with_strict_redacted_evidence(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_path = Path(temporary_directory)
            target_file, ssh_key = write_strict_target_configuration(
                temporary_path
            )
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
                    remote=SshRemotePreflight(InitialDeploymentProbe()),
                    authorization=DeclinedAuthorization(),
                ),
            )

            self.assertEqual(result.highest_state, "CI_VALIDATED")
            self.assertEqual(result.outcome, "CANCELLED")
            remote_check = next(
                check
                for check in result.checks
                if check.check_id == "remote_preflight"
            )
            self.assertEqual(remote_check.status, "PASS")
            evidence = json.loads(
                (
                    output_directory
                    / "deployments"
                    / result.run_id
                    / "remote-preflight.json"
                ).read_text(encoding="utf-8")
            )
            self.assertEqual(evidence["starting_state"], "INITIAL_DEPLOYMENT")
            self.assertEqual(evidence["result"], "PASS")
            retained = json.dumps(evidence)
            for sensitive_value in (
                "198.51.100.10",
                "203.0.113.9/32",
                str(ssh_key),
                "test-only-private-key",
            ):
                self.assertNotIn(sensitive_value, retained)

    def test_remote_transport_malfunction_is_redacted_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_path = Path(temporary_directory)
            target_file, _ = write_strict_target_configuration(
                temporary_path
            )
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
                    remote=SshRemotePreflight(MalfunctioningRemoteProbe()),
                ),
            )

            self.assertEqual(result.highest_state, "CI_VALIDATED")
            self.assertEqual(result.outcome, "ERROR")
            self.assertEqual(result.exit_code, 5)
            remote_check = next(
                check
                for check in result.checks
                if check.check_id == "remote_preflight"
            )
            self.assertEqual(remote_check.status, "ERROR")
            self.assertIn(
                "malfunction",
                remote_check.summary.lower(),
            )
            run_directory = (
                output_directory / "deployments" / result.run_id
            )
            self.assertFalse((run_directory / "remote-preflight.json").exists())
            retained = json.dumps(result.to_dict())
            for artifact in run_directory.iterdir():
                retained += artifact.read_text(encoding="utf-8")
            self.assertNotIn("sensitive transport diagnostic", retained)

    def test_privacy_expanding_remote_evidence_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_path = Path(temporary_directory)
            target_file, _ = write_strict_target_configuration(
                temporary_path
            )
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
                    remote=SshRemotePreflight(PrivacyExpandingRemoteProbe()),
                ),
            )

            self.assertEqual(result.outcome, "ERROR")
            self.assertEqual(result.highest_state, "CI_VALIDATED")
            run_directory = (
                output_directory / "deployments" / result.run_id
            )
            self.assertFalse((run_directory / "remote-preflight.json").exists())
            retained = "".join(
                path.read_text(encoding="utf-8")
                for path in run_directory.iterdir()
            )
            self.assertNotIn("198.51.100.10", retained)

    def test_production_ssh_transport_runs_the_bounded_remote_probe(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_path = Path(temporary_directory)
            target_file, _ = write_strict_target_configuration(
                temporary_path
            )
            fake_ssh = temporary_path / "ssh"
            fake_ssh.write_text(
                """#!/usr/bin/env python3
import base64
import json
import sys

required = {
    "BatchMode=yes",
    "IdentitiesOnly=yes",
    "StrictHostKeyChecking=yes",
    "ConnectTimeout=10",
}
if not required.issubset(set(sys.argv)):
    raise SystemExit(91)
if sys.argv[-2] != "-" or sys.argv[-3] != "python3":
    raise SystemExit(92)
probe = sys.stdin.buffer.read()
if b"EventHorizon remote preflight probe" not in probe:
    raise SystemExit(93)
request = json.loads(base64.urlsafe_b64decode(sys.argv[-1]))
print(json.dumps({
    "schema_version": 1,
    "target_alias": request["target_alias"],
    "deployment_commit": request["deployment_commit"],
    "checked_utc": "2026-07-30T01:02:03Z",
    "starting_state": "INITIAL_DEPLOYMENT",
    "result": "PASS",
    "checks": [{
        "id": "operating_system",
        "status": "PASS",
        "summary": "Authorized VPS runs Linux."
    }]
}))
""",
                encoding="utf-8",
            )
            fake_ssh.chmod(0o700)
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
                    remote=SshRemotePreflight(
                        SystemSshProbeTransport(
                            ssh_executable=fake_ssh,
                            probe_path=(
                                REPO_ROOT
                                / "scripts/vps_field_remote_probe.py"
                            ),
                        )
                    ),
                    authorization=DeclinedAuthorization(),
                ),
            )

            self.assertEqual(result.outcome, "CANCELLED")
            remote_check = next(
                check
                for check in result.checks
                if check.check_id == "remote_preflight"
            )
            self.assertEqual(remote_check.status, "PASS")

    def test_production_ssh_transport_runs_bounded_deployment_program(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_path = Path(temporary_directory)
            target_file, _ = write_strict_target_configuration(
                temporary_path
            )
            fake_ssh = temporary_path / "ssh"
            fake_ssh.write_text(
                """#!/usr/bin/env python3
import base64
import json
import sys

required = {
    "BatchMode=yes",
    "IdentitiesOnly=yes",
    "StrictHostKeyChecking=yes",
    "ConnectTimeout=10",
}
if not required.issubset(set(sys.argv)):
    raise SystemExit(91)
if sys.argv[-2] != "-" or sys.argv[-3] != "python3":
    raise SystemExit(92)
program = sys.stdin.buffer.read()
if b"EventHorizon exact-source remote deployment" not in program:
    raise SystemExit(93)
request = json.loads(base64.urlsafe_b64decode(sys.argv[-1]))
print(json.dumps({
    "schema_version": 1,
    "run_id": request["run_id"],
    "target_alias": request["target_alias"],
    "deployment_commit": request["deployment_commit"],
    "result": "BLOCKED",
    "blocker": "Injected post-authorization policy blocker.",
    "remote_mutation_occurred": True,
    "field_services_running": False,
    "compose_config": {},
    "deployment_manifest": {}
}))
""",
                encoding="utf-8",
            )
            fake_ssh.chmod(0o700)

            result = run(
                DeploymentRequest(
                    check_only=False,
                    commit="1" * 40,
                    env_file=target_file,
                    output_dir=temporary_path / "evidence",
                ),
                ControllerAdapters(
                    clock=FixedClock(),
                    randomness=FixedRandomSource(),
                    repository=ProvenRepository(),
                    trusted_ci=ProvenTrustedCi(),
                    remote=ReadyRemote(),
                    authorization=ApprovedAuthorization(),
                    deployment=SshExactSourceDeployment(
                        SystemSshDeploymentTransport(
                            ssh_executable=fake_ssh,
                            deployment_program_path=(
                                REPO_ROOT
                                / "scripts/vps_field_remote_deploy.py"
                            ),
                        )
                    ),
                ),
            )

            self.assertTrue(result.remote_mutation_occurred)
            self.assertFalse(result.field_services_running)
            deployment_check = next(
                check
                for check in result.checks
                if check.check_id == "exact_source_deployment"
            )
            self.assertEqual(deployment_check.status, "BLOCKER")

    def test_privacy_expanding_deployment_evidence_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_path = Path(temporary_directory)
            target_file, _ = write_strict_target_configuration(
                temporary_path
            )
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
                    remote=ReadyRemote(),
                    authorization=ApprovedAuthorization(),
                    deployment=SshExactSourceDeployment(
                        PrivacyExpandingDeploymentTransport()
                    ),
                ),
            )

            self.assertEqual(result.outcome, "ERROR")
            self.assertEqual(result.highest_state, "CI_VALIDATED")
            run_directory = (
                output_directory / "deployments" / result.run_id
            )
            self.assertFalse((run_directory / "compose-config.json").exists())
            self.assertFalse(
                (run_directory / "deployment-manifest.json").exists()
            )
            retained = "".join(
                path.read_text(encoding="utf-8")
                for path in run_directory.iterdir()
            )
            self.assertNotIn("198.51.100.10", retained)

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
