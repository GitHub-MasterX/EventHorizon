import base64
import hashlib
import http.server
import io
import json
import os
import re
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator, ValidationError
import scripts.deployment_controller as deployment_controller

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
    RemoteRuntimeExecution,
    SshExactSourceDeployment,
    SshRemotePreflight,
    SshRuntimeVerification,
    SystemSshDeploymentTransport,
    SystemSshProbeTransport,
    SystemSshRuntimeTransport,
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
        self.assertIn(
            "scripts/vps_field_remote_runtime.py",
            policy["protected_paths"],
        )
        self.assertIn(
            "scripts/vps_field_remote_smoke.py",
            policy["protected_paths"],
        )
        self.assertIn(".github/workflows/ci.yml", policy["protected_paths"])
        self.assertIn(
            "deploy/schemas/remote-preflight.schema.json",
            policy["protected_paths"],
        )
        self.assertIn(
            "deploy/schemas/health-and-ports.schema.json",
            policy["protected_paths"],
        )
        self.assertIn(
            "deploy/schemas/protocol-smoke.schema.json",
            policy["protected_paths"],
        )
        self.assertEqual(policy["remote_preflight_schema_version"], 2)
        self.assertEqual(policy["compose_config_schema_version"], 1)
        self.assertEqual(policy["deployment_manifest_schema_version"], 1)
        self.assertEqual(policy["health_and_ports_schema_version"], 1)
        self.assertEqual(policy["protocol_smoke_schema_version"], 1)

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
            "schema_version": 2,
            "target_alias": "field-host",
            "deployment_commit": "1" * 40,
            "checked_utc": "2026-07-30T01:02:03Z",
            "starting_state": "INITIAL_DEPLOYMENT",
            "managed_checkout_commit": None,
            "prior_evidence_commit": None,
            "interrupted_redeployment": False,
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
        managed_evidence = dict(
            evidence,
            starting_state="MANAGED_REDEPLOYMENT",
            managed_checkout_commit="2" * 40,
            prior_evidence_commit="1" * 40,
            interrupted_redeployment=True,
        )
        validator.validate(managed_evidence)
        with self.assertRaises(ValidationError):
            validator.validate(
                dict(
                    managed_evidence,
                    managed_checkout_commit=None,
                )
            )
        with self.assertRaises(ValidationError):
            validator.validate(dict(evidence, vps_host="198.51.100.10"))
        with self.assertRaises(ValidationError):
            validator.validate(dict(evidence, schema_version=1))

    def test_health_and_ports_schema_is_strict_and_redacted(self) -> None:
        schema = json.loads(
            (
                REPO_ROOT
                / "deploy/schemas/health-and-ports.schema.json"
            ).read_text(encoding="utf-8")
        )
        evidence = {
            "schema_version": 1,
            "run_id": "deploy-20260730T010203Z-a1b2c3",
            "target_alias": "field-host",
            "deployment_commit": "1" * 40,
            "checked_utc": "2026-07-30T01:02:03Z",
            "result": "PASS",
            "services": [
                {
                    "name": service,
                    "state": "RUNNING",
                    "health": "HEALTHY",
                    "restart_count": 0,
                    "oom_killed": False,
                    "image_id_verified": True,
                }
                for service in (
                    "cadvisor",
                    "grafana",
                    "mqtt_pit",
                    "prometheus",
                    "prometheus-exporter",
                    "telnet_pit",
                )
            ],
            "bindings": [
                {
                    "service": service,
                    "container_port": container_port,
                    "host_port": host_port,
                    "scope": scope,
                    "result": "PASS",
                }
                for service, container_port, host_port, scope in (
                    ("cadvisor", 8080, 8081, "LOOPBACK"),
                    ("grafana", 3000, 3000, "LOOPBACK"),
                    ("mqtt_pit", 1883, 1883, "PUBLIC"),
                    ("prometheus", 9090, 9090, "LOOPBACK"),
                    (
                        "prometheus-exporter",
                        9101,
                        9101,
                        "LOOPBACK",
                    ),
                    ("telnet_pit", 23, 23, "PUBLIC"),
                )
            ],
            "management_endpoints": [
                {
                    "service": service,
                    "port": port,
                    "result": "READY",
                }
                for service, port in (
                    ("cadvisor", 8081),
                    ("grafana", 3000),
                    ("prometheus", 9090),
                    ("prometheus-exporter", 9101),
                )
            ],
            "workstation_ports": [
                {
                    "port": port,
                    "expected": expected,
                    "observed": expected,
                    "result": "PASS",
                }
                for port, expected in (
                    (23, "REACHABLE"),
                    (1883, "REACHABLE"),
                    (3000, "UNREACHABLE"),
                    (8081, "UNREACHABLE"),
                    (9090, "UNREACHABLE"),
                    (9101, "UNREACHABLE"),
                )
            ],
            "cleanup": {
                "attempted": False,
                "succeeded": None,
            },
        }
        validator = Draft202012Validator(
            schema,
            format_checker=Draft202012Validator.FORMAT_CHECKER,
        )

        validator.validate(evidence)
        missing_healthcheck = json.loads(json.dumps(evidence))
        next(
            service
            for service in missing_healthcheck["services"]
            if service["name"] == "cadvisor"
        )["health"] = "NOT_CONFIGURED"
        with self.assertRaises(ValidationError):
            validator.validate(missing_healthcheck)
        validator.validate(
            {
                **evidence,
                "result": "ERROR",
                "services": [],
                "bindings": [],
                "management_endpoints": [],
                "workstation_ports": [],
                "cleanup": {
                    "attempted": True,
                    "succeeded": False,
                },
            }
        )
        with self.assertRaises(ValidationError):
            validator.validate(dict(evidence, vps_host="198.51.100.10"))
        with self.assertRaises(ValidationError):
            validator.validate(dict(evidence, schema_version=2))
        with self.assertRaises(ValidationError):
            validator.validate(
                dict(
                    evidence,
                    cleanup={"attempted": True, "succeeded": True},
                )
            )

    def test_protocol_smoke_schema_accepts_complete_and_partial_runs(self) -> None:
        schema = json.loads(
            (
                REPO_ROOT / "deploy/schemas/protocol-smoke.schema.json"
            ).read_text(encoding="utf-8")
        )
        snapshot = {
            "captured_utc": "2026-07-30T01:02:03Z",
            "scrape_utc": "2026-07-30T01:02:02Z",
            "malformed_messages": 0,
            "protocols": [
                {
                    "protocol": protocol,
                    "connections": 10,
                    "completed_sessions": 10,
                    "active_sessions": 0,
                    "depth_0": 2,
                    "depth_1": 2,
                    "depth_2": 4,
                    "depth_3": 2,
                    "duration_count": 10,
                    "duration_inf": 10,
                    "application_bytes_received": 100,
                    "application_bytes_sent": 200,
                    "restart_count": 0,
                    "oom_killed": False,
                    "image_id_verified": True,
                }
                for protocol in ("telnet", "mqtt")
            ],
        }
        final = json.loads(json.dumps(snapshot))
        final["captured_utc"] = "2026-07-30T01:02:20Z"
        final["scrape_utc"] = "2026-07-30T01:02:17Z"
        for protocol in final["protocols"]:
            protocol["connections"] += 1
            protocol["completed_sessions"] += 1
            protocol["depth_2"] += 1
            protocol["duration_count"] += 1
            protocol["duration_inf"] += 1
            protocol["application_bytes_received"] += 8
            protocol["application_bytes_sent"] += 4
        evidence = {
            "schema_version": 1,
            "run_id": "deploy-20260730T010203Z-a1b2c3",
            "target_alias": "field-host",
            "deployment_commit": "1" * 40,
            "started_utc": "2026-07-30T01:02:03Z",
            "finished_utc": "2026-07-30T01:02:20Z",
            "result": "PASS",
            "reason_code": "SMOKE_PASSED",
            "client_implementation": "PYTHON_STDLIB",
            "baseline": snapshot,
            "final": final,
            "clients": [
                {
                    "protocol": protocol,
                    "result": "PASS",
                    "bytes_written": 8,
                    "bytes_read": 4,
                }
                for protocol in ("telnet", "mqtt")
            ],
            "protocols": [
                {
                    "protocol": protocol,
                    "result": "PASS",
                    "deltas": {
                        "connections": 1,
                        "completed_sessions": 1,
                        "depth_total": 1,
                        "depth_2": 1,
                        "duration_count": 1,
                        "duration_inf": 1,
                        "application_bytes_received": 8,
                        "application_bytes_sent": 4,
                        "malformed_messages": 0,
                        "restarts": 0,
                    },
                    "checks": {
                        "exact_connection": True,
                        "exact_completion": True,
                        "active_settled": True,
                        "exact_depth_total": True,
                        "exact_depth_2": True,
                        "exact_duration_count": True,
                        "exact_duration_inf": True,
                        "positive_bytes_received": True,
                        "positive_bytes_sent": True,
                        "malformed_unchanged": True,
                        "restart_unchanged": True,
                        "oom_not_observed": True,
                        "lifecycle_reconciled": True,
                        "depth_reconciled": True,
                        "duration_reconciled": True,
                    },
                }
                for protocol in ("telnet", "mqtt")
            ],
            "cleanup": {"attempted": False, "succeeded": None},
        }
        validator = Draft202012Validator(
            schema,
            format_checker=Draft202012Validator.FORMAT_CHECKER,
        )

        validator.validate(evidence)
        validator.validate(
            {
                **evidence,
                "result": "BLOCKED",
                "reason_code": "CLEAN_BASELINE_UNAVAILABLE",
                "baseline": None,
                "final": None,
                "clients": [],
                "protocols": [],
                "cleanup": {"attempted": True, "succeeded": True},
            }
        )
        with self.assertRaises(ValidationError):
            validator.validate(dict(evidence, vps_host="198.51.100.10"))
        with self.assertRaises(ValidationError):
            validator.validate(dict(evidence, schema_version=2))
        inconsistent_pass = json.loads(json.dumps(evidence))
        inconsistent_pass["protocols"][0]["deltas"]["connections"] = 2
        with self.assertRaises(ValidationError):
            validator.validate(inconsistent_pass)

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
        self.assertIn(
            "scripts/vps_field_remote_smoke.py",
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

    def test_internal_remote_runtime_help_is_side_effect_free(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_path = Path(temporary_directory)

            completed = subprocess.run(
                [
                    sys.executable,
                    str(
                        REPO_ROOT
                        / "scripts/vps_field_remote_runtime.py"
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
                "usage: vps_field_remote_runtime.py <encoded-request>",
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
                "schema_version": 2,
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
    elif arguments == [
        "compose",
        "ls",
        "--all",
        "--format",
        "json",
    ]:
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
                "schema_version": 2,
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
            self.assertIsNone(evidence["managed_checkout_commit"])
            self.assertIsNone(evidence["prior_evidence_commit"])
            self.assertFalse(evidence["interrupted_redeployment"])
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

    def test_reconciled_stopped_project_is_managed_redeployment(
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
        print("[]")
    elif arguments == ["compose", "ls", "--all", "--format", "json"]:
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
    if (
        arguments != ["--version"]
        and os.environ.get("FAKE_STOPPED_PROJECT") != "1"
    ):
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
                "schema_version": 2,
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
            environment["FAKE_STOPPED_PROJECT"] = "1"

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
            self.assertEqual(
                evidence["managed_checkout_commit"],
                current_commit,
            )
            self.assertEqual(
                evidence["prior_evidence_commit"],
                current_commit,
            )
            self.assertFalse(evidence["interrupted_redeployment"])
            self.assertEqual(git("rev-parse", "HEAD"), current_commit)
            self.assertEqual(git("status", "--porcelain"), "")

            (
                deployment_evidence / "deployment-manifest.json"
            ).unlink()
            deployment_evidence.rmdir()
            (validation_output / "deployment_manifest.json").write_text(
                json.dumps(
                    {
                        "repository_commit": current_commit,
                        "compose_project_name": "eventhorizon-field",
                    }
                ),
                encoding="utf-8",
            )
            (deploy_dir / "tracked.txt").write_text(
                "interrupted deployment checkout\n",
                encoding="utf-8",
            )
            git("add", "tracked.txt")
            git("commit", "-qm", "interrupted deployment candidate")
            interrupted_commit = git("rev-parse", "HEAD")
            git(
                "update-ref",
                "refs/remotes/origin/GSoC_2026",
                interrupted_commit,
            )

            interrupted = subprocess.run(
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
            self.assertEqual(interrupted.returncode, 0, interrupted.stderr)
            interrupted_evidence = json.loads(interrupted.stdout)
            self.assertEqual(
                interrupted_evidence["result"],
                "PASS",
                interrupted.stdout,
            )
            self.assertEqual(
                interrupted_evidence["starting_state"],
                "MANAGED_REDEPLOYMENT",
            )
            self.assertEqual(
                interrupted_evidence["managed_checkout_commit"],
                interrupted_commit,
            )
            self.assertEqual(
                interrupted_evidence["prior_evidence_commit"],
                current_commit,
            )
            self.assertTrue(
                interrupted_evidence["interrupted_redeployment"]
            )
            recovery_check = next(
                check
                for check in interrupted_evidence["checks"]
                if check["id"] == "interrupted_redeployment"
            )
            self.assertEqual(recovery_check["status"], "WARNING")

            git(
                "update-ref",
                "refs/remotes/origin/GSoC_2026",
                current_commit,
            )
            untrusted_checkout = subprocess.run(
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
                untrusted_checkout.returncode,
                0,
                untrusted_checkout.stderr,
            )
            untrusted_evidence = json.loads(untrusted_checkout.stdout)
            self.assertEqual(untrusted_evidence["result"], "BLOCKED")
            prior_check = next(
                check
                for check in untrusted_evidence["checks"]
                if check["id"] == "prior_deployment_evidence"
            )
            self.assertEqual(prior_check["status"], "BLOCKER")
            git(
                "update-ref",
                "refs/remotes/origin/GSoC_2026",
                interrupted_commit,
            )

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


def successful_remote_runtime_evidence(
    commit: str,
    run_id: str,
) -> dict[str, object]:
    services = (
        "cadvisor",
        "grafana",
        "mqtt_pit",
        "prometheus",
        "prometheus-exporter",
        "telnet_pit",
    )
    return {
        "schema_version": 1,
        "run_id": run_id,
        "target_alias": "field-host",
        "deployment_commit": commit,
        "checked_utc": "2026-07-30T01:02:03Z",
        "result": "PASS",
        "blocker": None,
        "field_services_running": True,
        "services": [
            {
                "name": service,
                "state": "RUNNING",
                "health": "HEALTHY",
                "restart_count": 0,
                "oom_killed": False,
                "image_id_verified": True,
            }
            for service in services
        ],
        "bindings": [
            {
                "service": service,
                "container_port": container_port,
                "host_port": host_port,
                "scope": scope,
                "result": "PASS",
            }
            for service, container_port, host_port, scope in (
                ("cadvisor", 8080, 8081, "LOOPBACK"),
                ("grafana", 3000, 3000, "LOOPBACK"),
                ("mqtt_pit", 1883, 1883, "PUBLIC"),
                ("prometheus", 9090, 9090, "LOOPBACK"),
                (
                    "prometheus-exporter",
                    9101,
                    9101,
                    "LOOPBACK",
                ),
                ("telnet_pit", 23, 23, "PUBLIC"),
            )
        ],
        "management_endpoints": [
            {
                "service": service,
                "port": port,
                "result": "READY",
            }
            for service, port in (
                ("cadvisor", 8081),
                ("grafana", 3000),
                ("prometheus", 9090),
                ("prometheus-exporter", 9101),
            )
        ],
    }


def successful_protocol_smoke_evidence(
    commit: str,
    run_id: str,
) -> dict[str, object]:
    baseline = {
        "captured_utc": "2026-07-30T01:02:03Z",
        "scrape_utc": "2026-07-30T01:02:02Z",
        "malformed_messages": 0,
        "protocols": [
            {
                "protocol": protocol,
                "connections": 10,
                "completed_sessions": 10,
                "active_sessions": 0,
                "depth_0": 2,
                "depth_1": 2,
                "depth_2": 4,
                "depth_3": 2,
                "duration_count": 10,
                "duration_inf": 10,
                "application_bytes_received": 100,
                "application_bytes_sent": 200,
                "restart_count": 0,
                "oom_killed": False,
                "image_id_verified": True,
            }
            for protocol in ("telnet", "mqtt")
        ],
    }
    final = json.loads(json.dumps(baseline))
    final["captured_utc"] = "2026-07-30T01:02:20Z"
    final["scrape_utc"] = "2026-07-30T01:02:17Z"
    for protocol in final["protocols"]:
        protocol["connections"] += 1
        protocol["completed_sessions"] += 1
        protocol["depth_2"] += 1
        protocol["duration_count"] += 1
        protocol["duration_inf"] += 1
        protocol["application_bytes_received"] += 8
        protocol["application_bytes_sent"] += 4
    checks = {
        "exact_connection": True,
        "exact_completion": True,
        "active_settled": True,
        "exact_depth_total": True,
        "exact_depth_2": True,
        "exact_duration_count": True,
        "exact_duration_inf": True,
        "positive_bytes_received": True,
        "positive_bytes_sent": True,
        "malformed_unchanged": True,
        "restart_unchanged": True,
        "oom_not_observed": True,
        "lifecycle_reconciled": True,
        "depth_reconciled": True,
        "duration_reconciled": True,
    }
    return {
        "schema_version": 1,
        "run_id": run_id,
        "target_alias": "field-host",
        "deployment_commit": commit,
        "started_utc": "2026-07-30T01:02:03Z",
        "finished_utc": "2026-07-30T01:02:20Z",
        "result": "PASS",
        "reason_code": "SMOKE_PASSED",
        "client_implementation": "PYTHON_STDLIB",
        "baseline": baseline,
        "final": final,
        "clients": [
            {
                "protocol": protocol,
                "result": "PASS",
                "bytes_written": 8,
                "bytes_read": 4,
            }
            for protocol in ("telnet", "mqtt")
        ],
        "protocols": [
            {
                "protocol": protocol,
                "result": "PASS",
                "deltas": {
                    "connections": 1,
                    "completed_sessions": 1,
                    "depth_total": 1,
                    "depth_2": 1,
                    "duration_count": 1,
                    "duration_inf": 1,
                    "application_bytes_received": 8,
                    "application_bytes_sent": 4,
                    "malformed_messages": 0,
                    "restarts": 0,
                },
                "checks": checks,
            }
            for protocol in ("telnet", "mqtt")
        ],
        "cleanup": {"attempted": False, "succeeded": None},
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
                "managed_checkout_commit": None,
                "prior_evidence_commit": None,
                "interrupted_redeployment": False,
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
                "managed_checkout_commit": None,
                "prior_evidence_commit": None,
                "interrupted_redeployment": False,
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
            stale_preflight_request = dict(
                request,
                run_id="deploy-20260730T170050Z-b2c3d4",
                deployment_commit=deployment_commit,
                starting_state="MANAGED_REDEPLOYMENT",
                managed_checkout_commit="f" * 40,
                prior_evidence_commit=deployment_commit,
                interrupted_redeployment=True,
            )
            stale_preflight = subprocess.run(
                [
                    sys.executable,
                    str(
                        REPO_ROOT
                        / "scripts/vps_field_remote_deploy.py"
                    ),
                    base64.urlsafe_b64encode(
                        json.dumps(stale_preflight_request).encode("utf-8")
                    ).decode("ascii"),
                ],
                text=True,
                capture_output=True,
                check=False,
                env=environment,
                timeout=30,
            )
            self.assertEqual(
                stale_preflight.returncode,
                0,
                stale_preflight.stderr,
            )
            stale_response = json.loads(stale_preflight.stdout)
            self.assertEqual(stale_response["result"], "BLOCKED")
            self.assertFalse(stale_response["remote_mutation_occurred"])
            self.assertEqual(
                git("-C", str(deploy_dir), "rev-parse", "HEAD"),
                deployment_commit,
            )

            failed_run_id = "deploy-20260730T170100Z-d4e5f6"
            failed_request = dict(
                request,
                run_id=failed_run_id,
                deployment_commit=git("rev-parse", "HEAD"),
                starting_state="MANAGED_REDEPLOYMENT",
                managed_checkout_commit=deployment_commit,
                prior_evidence_commit=deployment_commit,
                interrupted_redeployment=False,
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
                managed_checkout_commit=failed_request[
                    "deployment_commit"
                ],
                prior_evidence_commit=failed_request[
                    "deployment_commit"
                ],
            )
            self.assertEqual(
                git("-C", str(deploy_dir), "rev-parse", "HEAD"),
                recovery_request["managed_checkout_commit"],
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


class RemoteSmokeProgramIntegrationTests(unittest.TestCase):
    def test_remote_program_captures_a_fresh_zero_active_baseline(self) -> None:
        program_path = REPO_ROOT / "scripts/vps_field_remote_smoke.py"
        self.assertTrue(program_path.is_file())
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_path = Path(temporary_directory)
            fake_bin = temporary_path / "fake-bin"
            fake_bin.mkdir()
            commit = "1" * 40
            run_id = "deploy-20260730T010203Z-a1b2c3"
            expected_image_ids = {
                service: "sha256:" + str(index) * 64
                for index, service in enumerate(
                    (
                        "cadvisor",
                        "grafana",
                        "mqtt_pit",
                        "prometheus",
                        "prometheus-exporter",
                        "telnet_pit",
                    ),
                    start=1,
                )
            }
            fake_git = fake_bin / "git"
            fake_git.write_text(
                f"""#!/usr/bin/env python3
print({commit!r})
""",
                encoding="utf-8",
            )
            fake_git.chmod(0o755)
            fake_docker = fake_bin / "docker"
            fake_docker.write_text(
                f"""#!/usr/bin/env python3
import json
import sys

images = {json.dumps(expected_image_ids)}
if sys.argv[1:3] == ["ps", "-aq"]:
    service_filter = next(
        value for value in sys.argv if value.startswith("label=com.docker.compose.service=")
    )
    print("id-" + service_filter.rsplit("=", 1)[1])
elif sys.argv[1] == "inspect":
    service = sys.argv[2].removeprefix("id-")
    print(json.dumps([{{
        "Image": images[service],
        "RestartCount": 0,
        "State": {{"Status": "running", "OOMKilled": False}},
    }}]))
else:
    raise SystemExit(91)
""",
                encoding="utf-8",
            )
            fake_docker.chmod(0o755)

            class PrometheusHandler(http.server.BaseHTTPRequestHandler):
                marker_calls = 0

                def do_GET(self) -> None:
                    expression = urllib.parse.parse_qs(
                        urllib.parse.urlparse(self.path).query
                    )["query"][0]
                    if expression.startswith("max(timestamp("):
                        type(self).marker_calls += 1
                        if type(self).marker_calls == 1:
                            value = 100
                        elif type(self).marker_calls <= 3:
                            value = 101
                        elif type(self).marker_calls <= 6:
                            value = 102
                        else:
                            value = 103
                    elif "current_connected_clients" in expression:
                        value = 0
                    elif "total_connects" in expression:
                        value = 10
                    elif "completed_sessions_total" in expression:
                        value = 10
                    elif "session_interaction_depth_total" in expression:
                        depth = int(re.search(r'depth_level="([0-3])"', expression)[1])
                        value = (2, 2, 4, 2)[depth]
                    elif "session_duration_ms_count" in expression:
                        value = 10
                    elif "session_duration_ms_bucket" in expression:
                        value = 10
                    elif "bytes_received_total" in expression:
                        value = 100
                    elif "bytes_sent_total" in expression:
                        value = 200
                    elif "exporter_malformed_messages_total" in expression:
                        value = 0
                    else:
                        self.send_error(400)
                        return
                    payload = json.dumps(
                        {
                            "status": "success",
                            "data": {
                                "resultType": "vector",
                                "result": [
                                    {
                                        "metric": {},
                                        "value": [101, str(value)],
                                    }
                                ],
                            },
                        }
                    ).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)

                def log_message(self, *args: object) -> None:
                    pass

            server = http.server.ThreadingHTTPServer(
                ("127.0.0.1", 0),
                PrometheusHandler,
            )
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            request = {
                "schema_version": 1,
                "action": "BASELINE",
                "run_id": run_id,
                "target_alias": "field-host",
                "deployment_commit": commit,
                "deploy_dir": "/srv/eventhorizon-field",
                "project_name": "eventhorizon-field",
                "expected_image_ids": expected_image_ids,
                "baseline_scrape_utc": None,
                "prometheus_url": (
                    f"http://127.0.0.1:{server.server_address[1]}"
                ),
                "settle_timeout_seconds": 2,
            }
            environment = os.environ.copy()
            environment["PATH"] = f"{fake_bin}:{environment['PATH']}"

            def invoke(document: dict[str, object]) -> subprocess.CompletedProcess[str]:
                encoded_request = base64.urlsafe_b64encode(
                    json.dumps(document).encode("utf-8")
                ).decode("ascii")
                return subprocess.run(
                    [sys.executable, str(program_path), encoded_request],
                    text=True,
                    capture_output=True,
                    check=False,
                    env=environment,
                    timeout=10,
                )

            try:
                completed = invoke(request)
                baseline_evidence = json.loads(completed.stdout)
                final_completed = invoke(
                    {
                        **request,
                        "action": "FINAL",
                        "baseline_scrape_utc": baseline_evidence["snapshot"][
                            "scrape_utc"
                        ],
                    }
                )
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=3)

            self.assertEqual(completed.returncode, 0, completed.stderr)
            evidence = json.loads(completed.stdout)
            self.assertEqual(evidence["result"], "PASS")
            self.assertEqual(evidence["reason_code"], "SNAPSHOT_CAPTURED")
            self.assertEqual(evidence["snapshot"]["malformed_messages"], 0)
            self.assertEqual(
                [
                    protocol["active_sessions"]
                    for protocol in evidence["snapshot"]["protocols"]
                ],
                [0, 0],
            )
            self.assertNotIn("deploy_dir", evidence)
            self.assertNotIn("prometheus_url", evidence)
            self.assertEqual(
                final_completed.returncode,
                0,
                final_completed.stderr,
            )
            final_evidence = json.loads(final_completed.stdout)
            self.assertEqual(final_evidence["result"], "PASS")
            self.assertEqual(
                int(
                    datetime.fromisoformat(
                        final_evidence["snapshot"]["scrape_utc"].replace(
                            "Z", "+00:00"
                        )
                    ).timestamp()
                ),
                103,
            )


class RemoteRuntimeProgramIntegrationTests(unittest.TestCase):
    def test_exact_runtime_is_healthy_and_uses_supported_bindings(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_path = Path(temporary_directory)
            deploy_dir = temporary_path / "authorized/vps/eventhorizon-field"
            deploy_dir.mkdir(parents=True)

            def git(*arguments: str) -> str:
                return subprocess.run(
                    ["git", *arguments],
                    cwd=deploy_dir,
                    text=True,
                    capture_output=True,
                    check=True,
                ).stdout.strip()

            git("init", "-q")
            git("config", "user.name", "Runtime Test")
            git("config", "user.email", "runtime@example.invalid")
            (deploy_dir / ".gitignore").write_text(
                "validation-output/\n",
                encoding="utf-8",
            )
            (deploy_dir / "tracked.txt").write_text(
                "exact deployed source\n",
                encoding="utf-8",
            )
            git("add", ".")
            git("commit", "-qm", "exact deployed source")
            deployment_commit = git("rev-parse", "HEAD")

            services = (
                "cadvisor",
                "grafana",
                "mqtt_pit",
                "prometheus",
                "prometheus-exporter",
                "telnet_pit",
            )
            image_ids = {
                service: "sha256:" + str(index) * 64
                for index, service in enumerate(services, start=1)
            }
            tools = temporary_path / "tools"
            tools.mkdir()
            dispatcher = tools / "fake-runtime-tool"
            dispatcher.write_text(
                """#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path

tool = Path(sys.argv[0]).name
arguments = sys.argv[1:]
services = {
    "cadvisor": (8080, 8081, "127.0.0.1"),
    "grafana": (3000, 3000, "127.0.0.1"),
    "mqtt_pit": (1883, 1883, "0.0.0.0"),
    "prometheus": (9090, 9090, "127.0.0.1"),
    "prometheus-exporter": (9101, 9101, "127.0.0.1"),
    "telnet_pit": (23, 23, "0.0.0.0"),
}
if tool == "docker":
    if arguments and arguments[0] == "compose" and "ps" in arguments:
        print("container-" + arguments[-1])
    elif arguments and arguments[0] == "inspect":
        service = arguments[-1].removeprefix("container-")
        container_port, host_port, host_ip = services[service]
        state = {
            "Status": "running",
            "OOMKilled": False,
        }
        health = "healthy"
        transient_marker = os.environ.get(
            "FAKE_TRANSIENT_HEALTH_MARKER"
        )
        if (
            service == "grafana"
            and transient_marker
            and not Path(transient_marker).exists()
        ):
            Path(transient_marker).write_text("observed\\n")
            health = "starting"
        state["Health"] = {"Status": health}
        print(json.dumps({
            "Image": json.loads(os.environ["FAKE_IMAGE_IDS"])[service],
            "RestartCount": 0,
            "Config": {
                "Labels": {
                    "com.docker.compose.project": "eventhorizon-field",
                    "com.docker.compose.service": service,
                }
            },
            "State": state,
            "NetworkSettings": {
                "Ports": {
                    f"{container_port}/tcp": (
                        [{
                            "HostIp": host_ip,
                            "HostPort": str(host_port),
                        }]
                        + (
                            [{
                                "HostIp": "::",
                                "HostPort": str(host_port),
                            }]
                            if host_ip == "0.0.0.0"
                            else []
                        )
                    )
                }
            },
        }))
    elif arguments and arguments[0] == "ps":
        stopped = Path(os.environ["FAKE_STOP_MARKER"]).exists()
        if "-a" in arguments:
            for service in services:
                print(
                    f"container-{service}\\t"
                    f"eventhorizon-field\\t{service}"
                )
        elif not stopped:
            for service in services:
                print("container-" + service)
    elif arguments and arguments[0] == "stop":
        Path(os.environ["FAKE_STOP_MARKER"]).write_text("stopped\\n")
    else:
        raise SystemExit(81)
elif tool == "curl":
    raise SystemExit(0)
else:
    raise SystemExit(83)
""",
                encoding="utf-8",
            )
            dispatcher.chmod(0o700)
            for tool_name in ("docker", "curl"):
                (tools / tool_name).symlink_to(dispatcher)

            request = {
                "schema_version": 1,
                "action": "VERIFY",
                "run_id": "deploy-20260730T010203Z-a1b2c3",
                "target_alias": "field-host",
                "deployment_commit": deployment_commit,
                "deploy_dir": str(deploy_dir),
                "project_name": "eventhorizon-field",
                "expected_image_ids": image_ids,
            }
            environment = os.environ.copy()
            environment["PATH"] = (
                str(tools) + os.pathsep + environment["PATH"]
            )
            environment["FAKE_IMAGE_IDS"] = json.dumps(image_ids)
            stop_marker = temporary_path / "stopped"
            environment["FAKE_STOP_MARKER"] = str(stop_marker)
            completed = subprocess.run(
                [
                    sys.executable,
                    str(
                        REPO_ROOT
                        / "scripts/vps_field_remote_runtime.py"
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
            evidence = json.loads(completed.stdout)
            self.assertEqual(evidence["result"], "PASS", evidence)
            self.assertTrue(evidence["field_services_running"])
            self.assertEqual(
                {service["name"] for service in evidence["services"]},
                set(services),
            )
            self.assertTrue(
                all(
                    binding["result"] == "PASS"
                    for binding in evidence["bindings"]
                )
            )
            self.assertTrue(
                all(
                    endpoint["result"] == "READY"
                    for endpoint in evidence["management_endpoints"]
                )
            )
            self.assertNotIn(str(deploy_dir), completed.stdout)

            transient_marker = temporary_path / "transient-health"
            environment["FAKE_TRANSIENT_HEALTH_MARKER"] = str(
                transient_marker
            )
            transient_request = dict(
                request,
                run_id="deploy-20260730T010204Z-d4e5f6",
            )
            transient = subprocess.run(
                [
                    sys.executable,
                    str(
                        REPO_ROOT
                        / "scripts/vps_field_remote_runtime.py"
                    ),
                    base64.urlsafe_b64encode(
                        json.dumps(transient_request).encode("utf-8")
                    ).decode("ascii"),
                ],
                text=True,
                capture_output=True,
                check=False,
                env=environment,
                timeout=15,
            )
            self.assertEqual(
                transient.returncode,
                0,
                transient.stderr,
            )
            transient_evidence = json.loads(transient.stdout)
            self.assertEqual(
                transient_evidence["result"],
                "PASS",
                transient_evidence,
            )
            self.assertTrue(transient_marker.is_file())
            environment.pop("FAKE_TRANSIENT_HEALTH_MARKER")

            stop_request = dict(
                request,
                action="STOP",
                expected_image_ids={},
            )
            stopped = subprocess.run(
                [
                    sys.executable,
                    str(
                        REPO_ROOT
                        / "scripts/vps_field_remote_runtime.py"
                    ),
                    base64.urlsafe_b64encode(
                        json.dumps(stop_request).encode("utf-8")
                    ).decode("ascii"),
                ],
                text=True,
                capture_output=True,
                check=False,
                env=environment,
                timeout=10,
            )
            self.assertEqual(stopped.returncode, 0, stopped.stderr)
            stop_evidence = json.loads(stopped.stdout)
            self.assertEqual(stop_evidence["result"], "PASS")
            self.assertFalse(stop_evidence["field_services_running"])
            self.assertTrue(stop_marker.is_file())


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
                "managed_checkout_commit": None,
                "prior_evidence_commit": None,
                "interrupted_redeployment": False,
                "result": "PASS",
            },
            blocker=None,
        )


class InterruptedReadyRemote:
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
                "starting_state": "MANAGED_REDEPLOYMENT",
                "managed_checkout_commit": "2" * 40,
                "prior_evidence_commit": "1" * 40,
                "interrupted_redeployment": True,
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
                    "schema_version": 2,
                    "target_alias": "field-host",
                    "deployment_commit": commit,
                    "checked_utc": "2026-07-30T01:02:03Z",
                    "starting_state": "INITIAL_DEPLOYMENT",
                    "managed_checkout_commit": None,
                    "prior_evidence_commit": None,
                    "interrupted_redeployment": False,
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
                    "schema_version": 2,
                    "target_alias": "field-host",
                    "deployment_commit": commit,
                    "checked_utc": "2026-07-30T01:02:03Z",
                    "starting_state": "INITIAL_DEPLOYMENT",
                    "managed_checkout_commit": None,
                    "prior_evidence_commit": None,
                    "interrupted_redeployment": False,
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
    def test_deployment_smoke_accepts_exact_depth_two_reconciliation(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_path = Path(temporary_directory)
            configuration = TargetConfiguration(
                target_alias="field-host",
                vps_host="198.51.100.10",
                vps_user="deploy",
                vps_ssh_port=22,
                vps_ssh_key=temporary_path / "operator_key",
                vps_deploy_dir="/srv/eventhorizon-field",
                vps_project_name="eventhorizon-field",
                admin_source_cidr="203.0.113.9/32",
                field_tarpit_cpu_limit="0.50",
                field_tarpit_memory_limit=None,
            )
            commit = "1" * 40
            run_id = "deploy-20260730T010203Z-a1b2c3"
            expected = successful_protocol_smoke_evidence(commit, run_id)

            class Execution:
                returncode = 0
                stderr = b""

                def __init__(self, action: str, snapshot: object) -> None:
                    self.stdout = json.dumps(
                        {
                            "schema_version": 1,
                            "action": action,
                            "run_id": run_id,
                            "target_alias": "field-host",
                            "deployment_commit": commit,
                            "result": "PASS",
                            "reason_code": "SNAPSHOT_CAPTURED",
                            "snapshot": snapshot,
                        }
                    ).encode("utf-8")

            class RemoteSmoke:
                def capture_baseline(self, *args: object) -> object:
                    return Execution("BASELINE", expected["baseline"])

                def capture_final(self, *args: object) -> object:
                    return Execution("FINAL", expected["final"])

                def stop(self, *args: object) -> bool:
                    return True

            class ProtocolClients:
                def run(self, host: str) -> tuple[dict[str, object], ...]:
                    return tuple(expected["clients"])

            verification = deployment_controller.SshDeploymentSmoke(
                remote=RemoteSmoke(),
                clients=ProtocolClients(),
                clock=FixedClock(),
            ).verify(
                configuration,
                commit,
                {},
                {
                    "service_image_ids": {
                        service: "sha256:" + str(index) * 64
                        for index, service in enumerate(
                            (
                                "cadvisor",
                                "grafana",
                                "mqtt_pit",
                                "prometheus",
                                "prometheus-exporter",
                                "telnet_pit",
                            ),
                            start=1,
                        )
                    }
                },
                run_id,
            )

            self.assertTrue(verification.passed)
            self.assertEqual(verification.outcome, "PASS")
            self.assertTrue(verification.field_services_running)
            self.assertEqual(verification.evidence["result"], "PASS")
            self.assertEqual(
                [item["deltas"] for item in verification.evidence["protocols"]],
                [item["deltas"] for item in expected["protocols"]],
            )
            schema = json.loads(
                (
                    REPO_ROOT / "deploy/schemas/protocol-smoke.schema.json"
                ).read_text(encoding="utf-8")
            )
            Draft202012Validator(
                schema,
                format_checker=Draft202012Validator.FORMAT_CHECKER,
            ).validate(verification.evidence)

    def test_deployment_smoke_failure_stops_the_exact_managed_services(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_path = Path(temporary_directory)
            configuration = TargetConfiguration(
                target_alias="field-host",
                vps_host="198.51.100.10",
                vps_user="deploy",
                vps_ssh_port=22,
                vps_ssh_key=temporary_path / "operator_key",
                vps_deploy_dir="/srv/eventhorizon-field",
                vps_project_name="eventhorizon-field",
                admin_source_cidr="203.0.113.9/32",
                field_tarpit_cpu_limit="0.50",
                field_tarpit_memory_limit=None,
            )
            commit = "1" * 40
            run_id = "deploy-20260730T010203Z-a1b2c3"
            expected = successful_protocol_smoke_evidence(commit, run_id)
            final = json.loads(json.dumps(expected["final"]))
            mqtt = final["protocols"][1]
            mqtt["depth_2"] -= 1
            mqtt["depth_3"] += 1

            class Execution:
                returncode = 0
                stderr = b""

                def __init__(self, action: str, snapshot: object) -> None:
                    self.stdout = json.dumps(
                        {
                            "schema_version": 1,
                            "action": action,
                            "run_id": run_id,
                            "target_alias": "field-host",
                            "deployment_commit": commit,
                            "result": "PASS",
                            "reason_code": "SNAPSHOT_CAPTURED",
                            "snapshot": snapshot,
                        }
                    ).encode("utf-8")

            class RemoteSmoke:
                def capture_baseline(self, *args: object) -> object:
                    return Execution("BASELINE", expected["baseline"])

                def capture_final(self, *args: object) -> object:
                    return Execution("FINAL", final)

                def stop(self, *args: object) -> bool:
                    return True

            class ProtocolClients:
                def run(self, host: str) -> tuple[dict[str, object], ...]:
                    return tuple(expected["clients"])

            verification = deployment_controller.SshDeploymentSmoke(
                remote=RemoteSmoke(),
                clients=ProtocolClients(),
                clock=FixedClock(),
            ).verify(
                configuration,
                commit,
                {},
                {
                    "service_image_ids": {
                        service: "sha256:" + str(index) * 64
                        for index, service in enumerate(
                            (
                                "cadvisor",
                                "grafana",
                                "mqtt_pit",
                                "prometheus",
                                "prometheus-exporter",
                                "telnet_pit",
                            ),
                            start=1,
                        )
                    }
                },
                run_id,
            )

            self.assertFalse(verification.passed)
            self.assertEqual(verification.outcome, "FAIL")
            self.assertFalse(verification.field_services_running)
            self.assertEqual(
                verification.evidence["cleanup"],
                {"attempted": True, "succeeded": True},
            )
            self.assertFalse(
                verification.evidence["protocols"][1]["checks"][
                    "exact_depth_2"
                ]
            )
            schema = json.loads(
                (
                    REPO_ROOT / "deploy/schemas/protocol-smoke.schema.json"
                ).read_text(encoding="utf-8")
            )
            Draft202012Validator(
                schema,
                format_checker=Draft202012Validator.FORMAT_CHECKER,
            ).validate(verification.evidence)

    def test_deployment_smoke_blocks_when_clean_baseline_is_unavailable(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_path = Path(temporary_directory)
            configuration = TargetConfiguration(
                target_alias="field-host",
                vps_host="198.51.100.10",
                vps_user="deploy",
                vps_ssh_port=22,
                vps_ssh_key=temporary_path / "operator_key",
                vps_deploy_dir="/srv/eventhorizon-field",
                vps_project_name="eventhorizon-field",
                admin_source_cidr="203.0.113.9/32",
                field_tarpit_cpu_limit="0.50",
                field_tarpit_memory_limit=None,
            )
            commit = "1" * 40
            run_id = "deploy-20260730T010203Z-a1b2c3"
            expected = successful_protocol_smoke_evidence(commit, run_id)
            unsettled = json.loads(json.dumps(expected["baseline"]))
            unsettled["protocols"][0]["active_sessions"] = 1

            class Execution:
                returncode = 0
                stderr = b""
                stdout = json.dumps(
                    {
                        "schema_version": 1,
                        "action": "BASELINE",
                        "run_id": run_id,
                        "target_alias": "field-host",
                        "deployment_commit": commit,
                        "result": "BLOCKED",
                        "reason_code": "ACTIVE_SESSIONS_DID_NOT_SETTLE",
                        "snapshot": unsettled,
                    }
                ).encode("utf-8")

            class RemoteSmoke:
                def capture_baseline(self, *args: object) -> object:
                    return Execution()

                def capture_final(self, *args: object) -> object:
                    return Execution()

                def stop(self, *args: object) -> bool:
                    return True

            class ProtocolClients:
                def run(self, host: str) -> tuple[dict[str, object], ...]:
                    return tuple(expected["clients"])

            verification = deployment_controller.SshDeploymentSmoke(
                remote=RemoteSmoke(),
                clients=ProtocolClients(),
                clock=FixedClock(),
            ).verify(
                configuration,
                commit,
                {},
                {
                    "service_image_ids": {
                        service: "sha256:" + str(index) * 64
                        for index, service in enumerate(
                            (
                                "cadvisor",
                                "grafana",
                                "mqtt_pit",
                                "prometheus",
                                "prometheus-exporter",
                                "telnet_pit",
                            ),
                            start=1,
                        )
                    }
                },
                run_id,
            )

            self.assertFalse(verification.passed)
            self.assertEqual(verification.outcome, "BLOCKED")
            self.assertFalse(verification.field_services_running)
            self.assertEqual(verification.evidence["baseline"], unsettled)
            self.assertIsNone(verification.evidence["final"])
            self.assertEqual(verification.evidence["clients"], [])
            self.assertEqual(
                verification.evidence["reason_code"],
                "CLEAN_BASELINE_UNAVAILABLE",
            )
            schema = json.loads(
                (
                    REPO_ROOT / "deploy/schemas/protocol-smoke.schema.json"
                ).read_text(encoding="utf-8")
            )
            Draft202012Validator(
                schema,
                format_checker=Draft202012Validator.FORMAT_CHECKER,
            ).validate(verification.evidence)

    def test_deployment_smoke_counter_reset_is_inconclusive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_path = Path(temporary_directory)
            configuration = TargetConfiguration(
                target_alias="field-host",
                vps_host="198.51.100.10",
                vps_user="deploy",
                vps_ssh_port=22,
                vps_ssh_key=temporary_path / "operator_key",
                vps_deploy_dir="/srv/eventhorizon-field",
                vps_project_name="eventhorizon-field",
                admin_source_cidr="203.0.113.9/32",
                field_tarpit_cpu_limit="0.50",
                field_tarpit_memory_limit=None,
            )
            commit = "1" * 40
            run_id = "deploy-20260730T010203Z-a1b2c3"
            expected = successful_protocol_smoke_evidence(commit, run_id)
            final = json.loads(json.dumps(expected["final"]))
            final["protocols"][0]["connections"] = 0

            class Execution:
                returncode = 0
                stderr = b""

                def __init__(self, action: str, snapshot: object) -> None:
                    self.stdout = json.dumps(
                        {
                            "schema_version": 1,
                            "action": action,
                            "run_id": run_id,
                            "target_alias": "field-host",
                            "deployment_commit": commit,
                            "result": "PASS",
                            "reason_code": "SNAPSHOT_CAPTURED",
                            "snapshot": snapshot,
                        }
                    ).encode("utf-8")

            class RemoteSmoke:
                def capture_baseline(self, *args: object) -> object:
                    return Execution("BASELINE", expected["baseline"])

                def capture_final(self, *args: object) -> object:
                    return Execution("FINAL", final)

                def stop(self, *args: object) -> bool:
                    return True

            class ProtocolClients:
                def run(self, host: str) -> tuple[dict[str, object], ...]:
                    return tuple(expected["clients"])

            verification = deployment_controller.SshDeploymentSmoke(
                remote=RemoteSmoke(),
                clients=ProtocolClients(),
                clock=FixedClock(),
            ).verify(
                configuration,
                commit,
                {},
                {
                    "service_image_ids": {
                        service: "sha256:" + str(index) * 64
                        for index, service in enumerate(
                            (
                                "cadvisor",
                                "grafana",
                                "mqtt_pit",
                                "prometheus",
                                "prometheus-exporter",
                                "telnet_pit",
                            ),
                            start=1,
                        )
                    }
                },
                run_id,
            )

            self.assertFalse(verification.passed)
            self.assertEqual(verification.outcome, "INCONCLUSIVE")
            self.assertFalse(verification.field_services_running)
            self.assertEqual(
                verification.evidence["reason_code"],
                "METRIC_EVIDENCE_INSUFFICIENT",
            )
            self.assertEqual(
                verification.evidence["cleanup"],
                {"attempted": True, "succeeded": True},
            )

    def test_deployment_smoke_client_malfunction_is_redacted_error(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_path = Path(temporary_directory)
            configuration = TargetConfiguration(
                target_alias="field-host",
                vps_host="198.51.100.10",
                vps_user="deploy",
                vps_ssh_port=22,
                vps_ssh_key=temporary_path / "operator_key",
                vps_deploy_dir="/srv/eventhorizon-field",
                vps_project_name="eventhorizon-field",
                admin_source_cidr="203.0.113.9/32",
                field_tarpit_cpu_limit="0.50",
                field_tarpit_memory_limit=None,
            )
            commit = "1" * 40
            run_id = "deploy-20260730T010203Z-a1b2c3"
            expected = successful_protocol_smoke_evidence(commit, run_id)

            class Execution:
                returncode = 0
                stderr = b""
                stdout = json.dumps(
                    {
                        "schema_version": 1,
                        "action": "BASELINE",
                        "run_id": run_id,
                        "target_alias": "field-host",
                        "deployment_commit": commit,
                        "result": "PASS",
                        "reason_code": "SNAPSHOT_CAPTURED",
                        "snapshot": expected["baseline"],
                    }
                ).encode("utf-8")

            class RemoteSmoke:
                def capture_baseline(self, *args: object) -> object:
                    return Execution()

                def capture_final(self, *args: object) -> object:
                    return Execution()

                def stop(self, *args: object) -> bool:
                    return True

            class BrokenProtocolClients:
                def run(self, host: str) -> tuple[dict[str, object], ...]:
                    raise OSError("sensitive target transport detail")

            verification = deployment_controller.SshDeploymentSmoke(
                remote=RemoteSmoke(),
                clients=BrokenProtocolClients(),
                clock=FixedClock(),
            ).verify(
                configuration,
                commit,
                {},
                {
                    "service_image_ids": {
                        service: "sha256:" + str(index) * 64
                        for index, service in enumerate(
                            (
                                "cadvisor",
                                "grafana",
                                "mqtt_pit",
                                "prometheus",
                                "prometheus-exporter",
                                "telnet_pit",
                            ),
                            start=1,
                        )
                    }
                },
                run_id,
            )

            self.assertFalse(verification.passed)
            self.assertEqual(verification.outcome, "ERROR")
            self.assertFalse(verification.field_services_running)
            self.assertEqual(
                verification.evidence["reason_code"],
                "CLIENT_MALFUNCTION",
            )
            self.assertEqual(
                verification.evidence["baseline"],
                expected["baseline"],
            )
            self.assertNotIn(
                "sensitive target transport detail",
                json.dumps(verification.evidence),
            )

    def test_deployment_smoke_transport_malfunction_is_redacted_error(
        self,
    ) -> None:
        configuration = TargetConfiguration(
            target_alias="field-host",
            vps_host="198.51.100.10",
            vps_user="deploy",
            vps_ssh_port=22,
            vps_ssh_key=Path("/tmp/test-only-operator-key"),
            vps_deploy_dir="/srv/eventhorizon-field",
            vps_project_name="eventhorizon-field",
            admin_source_cidr="203.0.113.9/32",
            field_tarpit_cpu_limit="0.50",
            field_tarpit_memory_limit=None,
        )
        commit = "1" * 40
        run_id = "deploy-20260730T010203Z-a1b2c3"

        class BrokenRemoteSmoke:
            def capture_baseline(self, *args: object) -> object:
                raise OSError("sensitive SSH transport detail")

            def capture_final(self, *args: object) -> object:
                raise OSError("not reached")

            def stop(self, *args: object) -> bool:
                return True

        class ProtocolClients:
            def run(self, host: str) -> tuple[dict[str, object], ...]:
                return ()

        verification = deployment_controller.SshDeploymentSmoke(
            remote=BrokenRemoteSmoke(),
            clients=ProtocolClients(),
            clock=FixedClock(),
        ).verify(
            configuration,
            commit,
            {},
            {
                "service_image_ids": {
                    service: "sha256:" + str(index) * 64
                    for index, service in enumerate(
                        (
                            "cadvisor",
                            "grafana",
                            "mqtt_pit",
                            "prometheus",
                            "prometheus-exporter",
                            "telnet_pit",
                        ),
                        start=1,
                    )
                }
            },
            run_id,
        )

        self.assertFalse(verification.passed)
        self.assertEqual(verification.outcome, "ERROR")
        self.assertFalse(verification.field_services_running)
        self.assertEqual(
            verification.evidence["reason_code"],
            "REMOTE_TRANSPORT_MALFUNCTION",
        )
        self.assertIsNone(verification.evidence["baseline"])
        self.assertNotIn(
            "sensitive SSH transport detail",
            json.dumps(verification.evidence),
        )

    def test_deployment_smoke_without_fresh_final_scrape_is_inconclusive(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_path = Path(temporary_directory)
            configuration = TargetConfiguration(
                target_alias="field-host",
                vps_host="198.51.100.10",
                vps_user="deploy",
                vps_ssh_port=22,
                vps_ssh_key=temporary_path / "operator_key",
                vps_deploy_dir="/srv/eventhorizon-field",
                vps_project_name="eventhorizon-field",
                admin_source_cidr="203.0.113.9/32",
                field_tarpit_cpu_limit="0.50",
                field_tarpit_memory_limit=None,
            )
            commit = "1" * 40
            run_id = "deploy-20260730T010203Z-a1b2c3"
            expected = successful_protocol_smoke_evidence(commit, run_id)
            stale_final = json.loads(json.dumps(expected["baseline"]))

            class Execution:
                returncode = 0
                stderr = b""

                def __init__(self, action: str) -> None:
                    final = action == "FINAL"
                    self.stdout = json.dumps(
                        {
                            "schema_version": 1,
                            "action": action,
                            "run_id": run_id,
                            "target_alias": "field-host",
                            "deployment_commit": commit,
                            "result": "INCONCLUSIVE" if final else "PASS",
                            "reason_code": (
                                "FRESH_SCRAPE_UNAVAILABLE"
                                if final
                                else "SNAPSHOT_CAPTURED"
                            ),
                            "snapshot": (
                                stale_final if final else expected["baseline"]
                            ),
                        }
                    ).encode("utf-8")

            class RemoteSmoke:
                def capture_baseline(self, *args: object) -> object:
                    return Execution("BASELINE")

                def capture_final(self, *args: object) -> object:
                    return Execution("FINAL")

                def stop(self, *args: object) -> bool:
                    return True

            class ProtocolClients:
                def run(self, host: str) -> tuple[dict[str, object], ...]:
                    return tuple(expected["clients"])

            verification = deployment_controller.SshDeploymentSmoke(
                remote=RemoteSmoke(),
                clients=ProtocolClients(),
                clock=FixedClock(),
            ).verify(
                configuration,
                commit,
                {},
                {
                    "service_image_ids": {
                        service: "sha256:" + str(index) * 64
                        for index, service in enumerate(
                            (
                                "cadvisor",
                                "grafana",
                                "mqtt_pit",
                                "prometheus",
                                "prometheus-exporter",
                                "telnet_pit",
                            ),
                            start=1,
                        )
                    }
                },
                run_id,
            )

            self.assertFalse(verification.passed)
            self.assertEqual(verification.outcome, "INCONCLUSIVE")
            self.assertFalse(verification.field_services_running)
            self.assertEqual(
                verification.evidence["reason_code"],
                "METRIC_EVIDENCE_INSUFFICIENT",
            )
            self.assertEqual(verification.evidence["final"], stale_final)
            self.assertEqual(
                verification.evidence["clients"],
                expected["clients"],
            )

    def test_runtime_accepts_healthy_cadvisor_and_combines_port_evidence(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_path = Path(temporary_directory)
            target_file, _ = write_strict_target_configuration(temporary_path)
            configuration = TargetConfiguration(
                target_alias="field-host",
                vps_host="198.51.100.10",
                vps_user="deploy",
                vps_ssh_port=22,
                vps_ssh_key=temporary_path / "operator_key",
                vps_deploy_dir="/srv/eventhorizon-field",
                vps_project_name="eventhorizon-field",
                admin_source_cidr="203.0.113.9/32",
                field_tarpit_cpu_limit="0.50",
                field_tarpit_memory_limit=None,
            )
            commit = "1" * 40
            run_id = "deploy-20260730T010203Z-a1b2c3"
            services = (
                "cadvisor",
                "grafana",
                "mqtt_pit",
                "prometheus",
                "prometheus-exporter",
                "telnet_pit",
            )
            image_ids = {
                service: "sha256:" + str(index) * 64
                for index, service in enumerate(services, start=1)
            }
            remote_evidence = {
                "schema_version": 1,
                "run_id": run_id,
                "target_alias": "field-host",
                "deployment_commit": commit,
                "checked_utc": "2026-07-30T01:02:03Z",
                "result": "PASS",
                "blocker": None,
                "field_services_running": True,
                "services": [
                    {
                        "name": service,
                        "state": "RUNNING",
                        "health": "HEALTHY",
                        "restart_count": 0,
                        "oom_killed": False,
                        "image_id_verified": True,
                    }
                    for service in services
                ],
                "bindings": [
                    {
                        "service": service,
                        "container_port": container_port,
                        "host_port": host_port,
                        "scope": scope,
                        "result": "PASS",
                    }
                    for service, container_port, host_port, scope in (
                        ("cadvisor", 8080, 8081, "LOOPBACK"),
                        ("grafana", 3000, 3000, "LOOPBACK"),
                        ("mqtt_pit", 1883, 1883, "PUBLIC"),
                        ("prometheus", 9090, 9090, "LOOPBACK"),
                        (
                            "prometheus-exporter",
                            9101,
                            9101,
                            "LOOPBACK",
                        ),
                        ("telnet_pit", 23, 23, "PUBLIC"),
                    )
                ],
                "management_endpoints": [
                    {
                        "service": service,
                        "port": port,
                        "result": "READY",
                    }
                    for service, port in (
                        ("cadvisor", 8081),
                        ("grafana", 3000),
                        ("prometheus", 9090),
                        ("prometheus-exporter", 9101),
                    )
                ],
            }

            class RemoteRuntime:
                def inspect(
                    self,
                    target: object,
                    deployment_commit: str,
                    expected_image_ids: dict[str, str],
                    requested_run_id: str,
                ) -> RemoteRuntimeExecution:
                    return RemoteRuntimeExecution(
                        returncode=0,
                        stdout=json.dumps(remote_evidence).encode("utf-8"),
                        stderr=b"",
                    )

                def stop(
                    self,
                    target: object,
                    deployment_commit: str,
                    requested_run_id: str,
                ) -> bool:
                    raise AssertionError("passing verification must not stop")

            class WorkstationPorts:
                def observe(
                    self,
                    host: str,
                    ports: tuple[int, ...],
                ) -> dict[int, bool]:
                    return {
                        23: True,
                        1883: True,
                        3000: False,
                        8081: False,
                        9090: False,
                        9101: False,
                    }

            verification = SshRuntimeVerification(
                transport=RemoteRuntime(),
                workstation_ports=WorkstationPorts(),
                clock=FixedClock(),
            ).verify(
                configuration,
                commit,
                json.loads(
                    (
                        REPO_ROOT / "deploy/deployment-policy.json"
                    ).read_text(encoding="utf-8")
                ),
                {"service_image_ids": image_ids},
                run_id,
            )

            self.assertTrue(verification.passed)
            self.assertEqual(verification.outcome, "PASS")
            self.assertTrue(verification.field_services_running)
            self.assertEqual(
                verification.observed_public_ports,
                (23, 1883),
            )
            self.assertEqual(
                verification.observed_private_ports,
                (3000, 8081, 9090, 9101),
            )
            schema = json.loads(
                (
                    REPO_ROOT
                    / "deploy/schemas/health-and-ports.schema.json"
                ).read_text(encoding="utf-8")
            )
            Draft202012Validator(
                schema,
                format_checker=Draft202012Validator.FORMAT_CHECKER,
            ).validate(verification.evidence)

    def test_runtime_port_blocker_stops_the_exact_managed_services(
        self,
    ) -> None:
        commit = "1" * 40
        run_id = "deploy-20260730T010203Z-a1b2c3"
        configuration = TargetConfiguration(
            target_alias="field-host",
            vps_host="198.51.100.10",
            vps_user="deploy",
            vps_ssh_port=22,
            vps_ssh_key=Path("/tmp/test-operator-key"),
            vps_deploy_dir="/srv/eventhorizon-field",
            vps_project_name="eventhorizon-field",
            admin_source_cidr="203.0.113.9/32",
            field_tarpit_cpu_limit="0.50",
            field_tarpit_memory_limit=None,
        )
        remote_evidence = successful_remote_runtime_evidence(
            commit,
            run_id,
        )
        image_ids = {
            service["name"]: "sha256:" + str(index) * 64
            for index, service in enumerate(
                remote_evidence["services"],
                start=1,
            )
        }

        class CleanupRuntime:
            stopped = False

            def inspect(
                self,
                target: object,
                deployment_commit: str,
                expected_image_ids: dict[str, str],
                requested_run_id: str,
            ) -> RemoteRuntimeExecution:
                return RemoteRuntimeExecution(
                    returncode=0,
                    stdout=json.dumps(remote_evidence).encode("utf-8"),
                    stderr=b"",
                )

            def stop(
                self,
                target: object,
                deployment_commit: str,
                requested_run_id: str,
            ) -> bool:
                self.stopped = True
                return True

        class ExposedManagementPort:
            def observe(
                self,
                host: str,
                ports: tuple[int, ...],
            ) -> dict[int, bool]:
                return {
                    23: True,
                    1883: True,
                    3000: True,
                    8081: False,
                    9090: False,
                    9101: False,
                }

        transport = CleanupRuntime()
        verification = SshRuntimeVerification(
            transport=transport,
            workstation_ports=ExposedManagementPort(),
            clock=FixedClock(),
        ).verify(
            configuration,
            commit,
            {},
            {"service_image_ids": image_ids},
            run_id,
        )

        self.assertFalse(verification.passed)
        self.assertEqual(verification.outcome, "BLOCKED")
        self.assertFalse(verification.field_services_running)
        self.assertTrue(transport.stopped)
        self.assertEqual(
            verification.evidence["cleanup"],
            {"attempted": True, "succeeded": True},
        )
        port_3000 = next(
            port
            for port in verification.evidence["workstation_ports"]
            if port["port"] == 3000
        )
        self.assertEqual(port_3000["result"], "FAIL")
        schema = json.loads(
            (
                REPO_ROOT
                / "deploy/schemas/health-and-ports.schema.json"
            ).read_text(encoding="utf-8")
        )
        Draft202012Validator(
            schema,
            format_checker=Draft202012Validator.FORMAT_CHECKER,
        ).validate(verification.evidence)

    def test_runtime_malfunction_preserves_partial_cleanup_evidence(
        self,
    ) -> None:
        commit = "1" * 40
        run_id = "deploy-20260730T010203Z-a1b2c3"
        configuration = TargetConfiguration(
            target_alias="field-host",
            vps_host="198.51.100.10",
            vps_user="deploy",
            vps_ssh_port=22,
            vps_ssh_key=Path("/tmp/test-operator-key"),
            vps_deploy_dir="/srv/eventhorizon-field",
            vps_project_name="eventhorizon-field",
            admin_source_cidr="203.0.113.9/32",
            field_tarpit_cpu_limit="0.50",
            field_tarpit_memory_limit=None,
        )
        image_ids = {
            service: "sha256:" + str(index) * 64
            for index, service in enumerate(
                (
                    "cadvisor",
                    "grafana",
                    "mqtt_pit",
                    "prometheus",
                    "prometheus-exporter",
                    "telnet_pit",
                ),
                start=1,
            )
        }

        class MalformedRuntime:
            def inspect(
                self,
                target: object,
                deployment_commit: str,
                expected_image_ids: dict[str, str],
                requested_run_id: str,
            ) -> RemoteRuntimeExecution:
                return RemoteRuntimeExecution(
                    returncode=0,
                    stdout=b"{}",
                    stderr=b"sensitive remote detail",
                )

            def stop(
                self,
                target: object,
                deployment_commit: str,
                requested_run_id: str,
            ) -> bool:
                return True

        verification = SshRuntimeVerification(
            transport=MalformedRuntime(),
            workstation_ports=None,
            clock=FixedClock(),
        ).verify(
            configuration,
            commit,
            {},
            {"service_image_ids": image_ids},
            run_id,
        )

        self.assertFalse(verification.passed)
        self.assertEqual(verification.outcome, "ERROR")
        self.assertFalse(verification.field_services_running)
        self.assertEqual(verification.evidence["services"], [])
        self.assertEqual(
            verification.evidence["cleanup"],
            {"attempted": True, "succeeded": True},
        )
        self.assertNotIn(
            "sensitive remote detail",
            json.dumps(verification.evidence),
        )
        schema = json.loads(
            (
                REPO_ROOT
                / "deploy/schemas/health-and-ports.schema.json"
            ).read_text(encoding="utf-8")
        )
        Draft202012Validator(
            schema,
            format_checker=Draft202012Validator.FORMAT_CHECKER,
        ).validate(verification.evidence)

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

    def test_successful_deployment_smoke_advances_to_evidence_retrieval(
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

            health_and_ports = {
                "schema_version": 1,
                "run_id": "deploy-20260730T010203Z-a1b2c3",
                "target_alias": "field-host",
                "deployment_commit": commit,
                "checked_utc": "2026-07-30T01:02:03Z",
                "result": "PASS",
                "services": [
                    {
                        "name": service,
                        "state": "RUNNING",
                        "health": "HEALTHY",
                        "restart_count": 0,
                        "oom_killed": False,
                        "image_id_verified": True,
                    }
                    for service in (
                        "cadvisor",
                        "grafana",
                        "mqtt_pit",
                        "prometheus",
                        "prometheus-exporter",
                        "telnet_pit",
                    )
                ],
                "bindings": [
                    {
                        "service": service,
                        "container_port": container_port,
                        "host_port": host_port,
                        "scope": scope,
                        "result": "PASS",
                    }
                    for service, container_port, host_port, scope in (
                        ("cadvisor", 8080, 8081, "LOOPBACK"),
                        ("grafana", 3000, 3000, "LOOPBACK"),
                        ("mqtt_pit", 1883, 1883, "PUBLIC"),
                        ("prometheus", 9090, 9090, "LOOPBACK"),
                        (
                            "prometheus-exporter",
                            9101,
                            9101,
                            "LOOPBACK",
                        ),
                        ("telnet_pit", 23, 23, "PUBLIC"),
                    )
                ],
                "management_endpoints": [
                    {
                        "service": service,
                        "port": port,
                        "result": "READY",
                    }
                    for service, port in (
                        ("cadvisor", 8081),
                        ("grafana", 3000),
                        ("prometheus", 9090),
                        ("prometheus-exporter", 9101),
                    )
                ],
                "workstation_ports": [
                    {
                        "port": port,
                        "expected": expected,
                        "observed": observed,
                        "result": "PASS",
                    }
                    for port, expected, observed in (
                        (23, "REACHABLE", "REACHABLE"),
                        (1883, "REACHABLE", "REACHABLE"),
                        (3000, "UNREACHABLE", "UNREACHABLE"),
                        (8081, "UNREACHABLE", "UNREACHABLE"),
                        (9090, "UNREACHABLE", "UNREACHABLE"),
                        (9101, "UNREACHABLE", "UNREACHABLE"),
                    )
                ],
                "cleanup": {
                    "attempted": False,
                    "succeeded": None,
                },
            }

            class ReadyRuntime:
                def verify(
                    self,
                    configuration: object,
                    deployment_commit: str,
                    policy: dict[str, object],
                    deployment_manifest: dict[str, object],
                    run_id: str,
                ) -> object:
                    class Verification:
                        passed = True
                        outcome = "PASS"
                        blocker = None
                        field_services_running = True
                        evidence = health_and_ports
                        observed_public_ports = (23, 1883)
                        observed_private_ports = (3000, 8081, 9090, 9101)

                    return Verification()

            protocol_smoke = successful_protocol_smoke_evidence(
                commit,
                "deploy-20260730T010203Z-a1b2c3",
            )

            class ReadySmoke:
                def verify(
                    self,
                    configuration: object,
                    deployment_commit: str,
                    policy: dict[str, object],
                    deployment_manifest: dict[str, object],
                    run_id: str,
                ) -> object:
                    class Verification:
                        passed = True
                        outcome = "PASS"
                        blocker = None
                        field_services_running = True
                        evidence = protocol_smoke

                    return Verification()

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
                    runtime=ReadyRuntime(),
                    smoke=ReadySmoke(),
                ),
            )

            checks = {check.check_id: check for check in result.checks}
            self.assertEqual(checks["exact_source_deployment"].status, "PASS")
            self.assertEqual(
                checks["runtime_verification"].status,
                "PASS",
            )
            self.assertEqual(
                checks["deployment_smoke"].status,
                "PASS",
            )
            self.assertEqual(
                checks["evidence_retrieval_foundation"].status,
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
            self.assertEqual(
                json.loads(
                    (run_directory / "health-and-ports.json").read_text(
                        encoding="utf-8"
                    )
                ),
                health_and_ports,
            )
            self.assertEqual(
                json.loads(
                    (run_directory / "protocol-smoke.json").read_text(
                        encoding="utf-8"
                    )
                ),
                protocol_smoke,
            )
            authorization = json.loads(
                (run_directory / "authorization.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(
                authorization["observed_public_ports"],
                [23, 1883],
            )
            self.assertEqual(
                authorization["observed_private_ports"],
                [3000, 8081, 9090, 9101],
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
        self.assertIsNotNone(adapters.runtime)
        self.assertIsNotNone(adapters.smoke)

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
    "schema_version": 2,
    "target_alias": request["target_alias"],
    "deployment_commit": request["deployment_commit"],
    "checked_utc": "2026-07-30T01:02:03Z",
    "starting_state": "INITIAL_DEPLOYMENT",
    "managed_checkout_commit": None,
    "prior_evidence_commit": None,
    "interrupted_redeployment": False,
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
if (
    request.get("managed_checkout_commit") != "2" * 40
    or request.get("prior_evidence_commit") != "1" * 40
    or request.get("interrupted_redeployment") is not True
):
    raise SystemExit(94)
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
                    remote=InterruptedReadyRemote(),
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

    def test_production_ssh_transport_runs_bounded_runtime_program(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_path = Path(temporary_directory)
            _, ssh_key = write_strict_target_configuration(
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
if b"EventHorizon runtime health and binding evidence" not in program:
    raise SystemExit(93)
request = json.loads(base64.urlsafe_b64decode(sys.argv[-1]))
if request["action"] == "VERIFY":
    print(json.dumps({
        "schema_version": 1,
        "run_id": request["run_id"],
        "target_alias": request["target_alias"],
        "deployment_commit": request["deployment_commit"],
        "result": "BLOCKED",
    }))
else:
    if request["expected_image_ids"] != {}:
        raise SystemExit(94)
    print(json.dumps({
        "schema_version": 1,
        "action": "STOP",
        "run_id": request["run_id"],
        "target_alias": request["target_alias"],
        "deployment_commit": request["deployment_commit"],
        "result": "PASS",
        "blocker": None,
        "field_services_running": False,
    }))
""",
                encoding="utf-8",
            )
            fake_ssh.chmod(0o700)
            configuration = TargetConfiguration(
                target_alias="field-host",
                vps_host="198.51.100.10",
                vps_user="deploy",
                vps_ssh_port=22,
                vps_ssh_key=ssh_key,
                vps_deploy_dir="/srv/eventhorizon-field",
                vps_project_name="eventhorizon-field",
                admin_source_cidr="203.0.113.9/32",
                field_tarpit_cpu_limit="0.50",
                field_tarpit_memory_limit=None,
            )
            transport = SystemSshRuntimeTransport(
                ssh_executable=fake_ssh,
                runtime_program_path=(
                    REPO_ROOT
                    / "scripts/vps_field_remote_runtime.py"
                ),
            )
            image_ids = {
                service: "sha256:" + str(index) * 64
                for index, service in enumerate(
                    (
                        "cadvisor",
                        "grafana",
                        "mqtt_pit",
                        "prometheus",
                        "prometheus-exporter",
                        "telnet_pit",
                    ),
                    start=1,
                )
            }
            run_id = "deploy-20260730T010203Z-a1b2c3"
            commit = "1" * 40

            inspected = transport.inspect(
                configuration,
                commit,
                image_ids,
                run_id,
            )
            self.assertEqual(inspected.returncode, 0)
            self.assertEqual(
                json.loads(inspected.stdout)["result"],
                "BLOCKED",
            )
            self.assertTrue(
                transport.stop(
                    configuration,
                    commit,
                    run_id,
                )
            )

    def test_production_ssh_transport_streams_bounded_smoke_program(self) -> None:
        transport_class = deployment_controller.SystemSshSmokeTransport
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_path = Path(temporary_directory)
            _, ssh_key = write_strict_target_configuration(temporary_path)
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
if b"EventHorizon deterministic deployment-smoke snapshot collector" not in program:
    raise SystemExit(93)
request = json.loads(base64.urlsafe_b64decode(sys.argv[-1]))
if request["prometheus_url"] != "http://127.0.0.1:9090":
    raise SystemExit(94)
print(json.dumps({
    "action": request["action"],
    "baseline_scrape_utc": request["baseline_scrape_utc"],
}))
""",
                encoding="utf-8",
            )
            fake_ssh.chmod(0o700)
            configuration = TargetConfiguration(
                target_alias="field-host",
                vps_host="198.51.100.10",
                vps_user="deploy",
                vps_ssh_port=22,
                vps_ssh_key=ssh_key,
                vps_deploy_dir="/srv/eventhorizon-field",
                vps_project_name="eventhorizon-field",
                admin_source_cidr="203.0.113.9/32",
                field_tarpit_cpu_limit="0.50",
                field_tarpit_memory_limit=None,
            )
            image_ids = {
                service: "sha256:" + str(index) * 64
                for index, service in enumerate(
                    (
                        "cadvisor",
                        "grafana",
                        "mqtt_pit",
                        "prometheus",
                        "prometheus-exporter",
                        "telnet_pit",
                    ),
                    start=1,
                )
            }

            class Cleanup:
                def stop(self, *args: object) -> bool:
                    return True

            transport = transport_class(
                smoke_program_path=(
                    REPO_ROOT / "scripts/vps_field_remote_smoke.py"
                ),
                cleanup=Cleanup(),
                ssh_executable=fake_ssh,
            )
            baseline = transport.capture_baseline(
                configuration,
                "1" * 40,
                image_ids,
                "deploy-20260730T010203Z-a1b2c3",
            )
            final = transport.capture_final(
                configuration,
                "1" * 40,
                image_ids,
                "deploy-20260730T010203Z-a1b2c3",
                "2026-07-30T01:02:03Z",
            )

            self.assertEqual(baseline.returncode, 0)
            self.assertEqual(
                json.loads(baseline.stdout),
                {"action": "BASELINE", "baseline_scrape_utc": None},
            )
            self.assertEqual(
                json.loads(final.stdout),
                {
                    "action": "FINAL",
                    "baseline_scrape_utc": "2026-07-30T01:02:03Z",
                },
            )

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


class ProtocolSmokeClientIntegrationTests(unittest.TestCase):
    def test_standard_library_clients_run_one_telnet_and_mqtt_session(
        self,
    ) -> None:
        client_class = deployment_controller.SystemProtocolSmokeClients
        telnet_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        mqtt_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        for listener in (telnet_listener, mqtt_listener):
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            listener.settimeout(3)
        telnet_port = telnet_listener.getsockname()[1]
        mqtt_port = mqtt_listener.getsockname()[1]
        observed: dict[str, bytes] = {}
        errors: list[str] = []

        def serve_telnet() -> None:
            try:
                connection, _ = telnet_listener.accept()
                with connection:
                    connection.settimeout(2)
                    connection.sendall(b"controlled banner\r\n")
                    received = bytearray()
                    while True:
                        chunk = connection.recv(4096)
                        if not chunk:
                            break
                        received.extend(chunk)
                    observed["telnet"] = bytes(received)
            except Exception as error:  # test-server diagnostics only
                errors.append(type(error).__name__)

        def serve_mqtt() -> None:
            try:
                connection, _ = mqtt_listener.accept()
                with connection:
                    connection.settimeout(2)
                    connect_packet = bytearray(connection.recv(4096))
                    while len(connect_packet) < 2 + connect_packet[1]:
                        connect_packet.extend(connection.recv(4096))
                    connection.sendall(b"\x20\x02\x00\x00")
                    following = bytearray()
                    while b"\xe0\x00" not in following:
                        chunk = connection.recv(4096)
                        if not chunk:
                            break
                        following.extend(chunk)
                    observed["mqtt_connect"] = bytes(connect_packet)
                    observed["mqtt_following"] = bytes(following)
            except Exception as error:  # test-server diagnostics only
                errors.append(type(error).__name__)

        threads = [
            threading.Thread(target=serve_telnet, daemon=True),
            threading.Thread(target=serve_mqtt, daemon=True),
        ]
        for thread in threads:
            thread.start()
        try:
            results = client_class(
                telnet_port=telnet_port,
                mqtt_port=mqtt_port,
                timeout_seconds=2,
            ).run("127.0.0.1")
        finally:
            for listener in (telnet_listener, mqtt_listener):
                listener.close()
            for thread in threads:
                thread.join(timeout=3)

        self.assertEqual(errors, [])
        self.assertEqual(observed["telnet"], b"help\r\n")
        self.assertEqual(observed["mqtt_connect"][0] >> 4, 1)
        self.assertEqual(observed["mqtt_following"][0] >> 4, 3)
        self.assertTrue(observed["mqtt_following"].endswith(b"\xe0\x00"))
        self.assertEqual(
            [(item["protocol"], item["result"]) for item in results],
            [("telnet", "PASS"), ("mqtt", "PASS")],
        )
        self.assertTrue(all(item["bytes_written"] > 0 for item in results))


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
