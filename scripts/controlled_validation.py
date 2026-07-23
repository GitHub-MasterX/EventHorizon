#!/usr/bin/env python3
"""Bounded Telnet/MQTT client and evidence collector for the canonical runner."""

from __future__ import annotations

import argparse
import concurrent.futures
import csv
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


ACTIONS = (
    "connect", "disconnect", "read", "write", "banner", "mqtt_connect",
    "mqtt_publish", "mqtt_subscribe", "mqtt_disconnect", "mqtt_connack",
    "mqtt_pubrec", "mqtt_unsubscribe", "malformed_connect",
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def run(command: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=check, text=True, capture_output=True, timeout=20)


def prom_query(base_url: str, expression: str) -> list[dict]:
    query = urllib.parse.urlencode({"query": expression})
    with urllib.request.urlopen(f"{base_url.rstrip('/')}/api/v1/query?{query}", timeout=10) as response:
        payload = json.load(response)
    if payload.get("status") != "success":
        raise RuntimeError(f"Prometheus rejected query: {expression}")
    return payload.get("data", {}).get("result", [])


def prom_scalar(base_url: str, expression: str) -> float:
    result = prom_query(base_url, f"({expression}) or vector(0)")
    if len(result) != 1:
        raise RuntimeError(f"expected one Prometheus result for {expression!r}, got {len(result)}")
    return float(result[0]["value"][1])


def capture_metrics(base_url: str) -> dict[str, float]:
    metrics: dict[str, float] = {}
    for protocol, server in (("telnet", "Telnet"), ("mqtt", "MQTT")):
        metrics[f"connections.{protocol}"] = prom_scalar(base_url, f'sum(total_connects{{server="{server}"}})')
        metrics[f"completions.{protocol}"] = prom_scalar(base_url, f'sum(eventhorizon_completed_sessions_total{{protocol="{protocol}"}})')
        metrics[f"active.{protocol}"] = prom_scalar(base_url, f'sum(current_connected_clients{{server="{server}"}})')
        metrics[f"duration_count.{protocol}"] = prom_scalar(base_url, f'sum(eventhorizon_session_duration_ms_count{{protocol="{protocol}"}})')
        metrics[f"duration_inf.{protocol}"] = prom_scalar(base_url, f'sum(eventhorizon_session_duration_ms_bucket{{protocol="{protocol}",le="+Inf"}})')
        metrics[f"early_disconnect.{protocol}"] = prom_scalar(base_url, f'sum(eventhorizon_early_disconnect_total{{protocol="{protocol}"}})')
        metrics[f"rx_bytes.{protocol}"] = prom_scalar(base_url, f'sum(eventhorizon_bytes_received_total{{protocol="{protocol}"}})')
        metrics[f"tx_bytes.{protocol}"] = prom_scalar(base_url, f'sum(eventhorizon_bytes_sent_total{{protocol="{protocol}"}})')
        metrics[f"read_outcomes.{protocol}"] = prom_scalar(base_url, f'sum(eventhorizon_read_errors_total{{protocol="{protocol}"}})')
        metrics[f"write_outcomes.{protocol}"] = prom_scalar(base_url, f'sum(eventhorizon_write_errors_total{{protocol="{protocol}"}})')
        for depth in range(4):
            metrics[f"depth.{protocol}.{depth}"] = prom_scalar(
                base_url,
                f'sum(eventhorizon_session_interaction_depth_total{{protocol="{protocol}",depth_level="{depth}"}})',
            )
        for action in ACTIONS:
            metrics[f"action.{protocol}.{action}"] = prom_scalar(
                base_url,
                f'sum(eventhorizon_protocol_actions_total{{protocol="{protocol}",action="{action}"}})',
            )
        metrics[f"cpu_cores.{protocol}"] = prom_scalar(
            base_url,
            f'sum(rate(container_cpu_usage_seconds_total{{container_label_com_docker_compose_service="{protocol}_pit"}}[1m]))',
        )
        metrics[f"memory_bytes.{protocol}"] = prom_scalar(
            base_url,
            f'sum(container_memory_working_set_bytes{{container_label_com_docker_compose_service="{protocol}_pit"}})',
        )
        metrics[f"network_rx_bytes.{protocol}"] = prom_scalar(
            base_url,
            f'sum(container_network_receive_bytes_total{{container_label_com_docker_compose_service="{protocol}_pit"}})',
        )
        metrics[f"network_tx_bytes.{protocol}"] = prom_scalar(
            base_url,
            f'sum(container_network_transmit_bytes_total{{container_label_com_docker_compose_service="{protocol}_pit"}})',
        )
    metrics["malformed"] = prom_scalar(base_url, "sum(eventhorizon_exporter_malformed_messages_total)")
    for protocol, server in (("telnet", "Telnet"), ("mqtt", "MQTT")):
        metrics[f"lifecycle_gap.{protocol}"] = (
            metrics[f"connections.{protocol}"]
            - metrics[f"completions.{protocol}"]
            - metrics[f"active.{protocol}"]
        )
    return metrics


def write_metric_snapshot(path: Path, metrics: dict[str, float]) -> None:
    with path.open("w", encoding="utf-8", newline="") as output:
        output.write(f"captured_utc\t{utc_now()}\n")
        for key in sorted(metrics):
            output.write(f"{key}\t{metrics[key]:.12g}\n")
    path.chmod(0o600)


def container_id(project: str, service: str) -> str | None:
    result = run([
        "docker", "ps", "-aq",
        "--filter", f"label=com.docker.compose.project={project}",
        "--filter", f"label=com.docker.compose.service={service}",
    ])
    ids = [line for line in result.stdout.splitlines() if line]
    return ids[0] if len(ids) == 1 else None


def container_metadata(project: str) -> tuple[dict, dict[str, dict]]:
    images: dict[str, str] = {}
    limits: dict[str, dict] = {}
    for service in ("telnet_pit", "mqtt_pit", "prometheus-exporter", "prometheus", "grafana", "cadvisor"):
        cid = container_id(project, service)
        if not cid:
            continue
        inspected = json.loads(run(["docker", "inspect", cid]).stdout)[0]
        images[service] = inspected.get("Image", "unknown")
        host_config = inspected.get("HostConfig", {})
        limits[service] = {
            "memory_bytes": host_config.get("Memory", 0),
            "nano_cpus": host_config.get("NanoCpus", 0),
            "pids_limit": host_config.get("PidsLimit"),
        }
    return images, limits


def container_state(project: str, service: str) -> dict:
    cid = container_id(project, service)
    if not cid:
        return {"status": "missing", "restarts": -1, "oom": False}
    template = "{{json .State}}"
    state = json.loads(run(["docker", "inspect", "--format", template, cid]).stdout)
    return {
        "status": state.get("Status", "unknown"),
        "restarts": int(json.loads(run(["docker", "inspect", "--format", "{{json .RestartCount}}", cid]).stdout)),
        "oom": bool(state.get("OOMKilled", False)),
    }


def temperature_c() -> float | None:
    path = Path("/sys/class/thermal/thermal_zone0/temp")
    try:
        value = float(path.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return None
    return value / 1000 if value > 1000 else value


def docker_stats(cid: str | None) -> dict:
    if not cid:
        return {"CPUPerc": "", "MemUsage": "", "NetIO": ""}
    try:
        output = run(["docker", "stats", "--no-stream", "--format", "{{json .}}", cid]).stdout.strip()
        return json.loads(output) if output else {"CPUPerc": "", "MemUsage": "", "NetIO": ""}
    except (subprocess.SubprocessError, json.JSONDecodeError):
        return {"CPUPerc": "", "MemUsage": "", "NetIO": ""}


def monitor_resources(args, baseline: dict, done: threading.Event, stop: threading.Event, csv_path: Path, reasons: list[str]) -> None:
    headers = [
        "timestamp_utc", "service", "cpu_percent", "memory_usage", "network_io",
        "restarts", "oom_killed", "temperature_c", "disk_available_bytes", "status",
    ]
    persistent_gap = 0
    with csv_path.open("w", encoding="utf-8", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=headers)
        writer.writeheader()
        while True:
            disk_available = shutil.disk_usage(args.run_dir).free
            temp = temperature_c()
            for service in ("telnet_pit", "mqtt_pit"):
                state = container_state(args.compose_project, service)
                stats = docker_stats(container_id(args.compose_project, service))
                writer.writerow({
                    "timestamp_utc": utc_now(),
                    "service": service,
                    "cpu_percent": stats.get("CPUPerc", ""),
                    "memory_usage": stats.get("MemUsage", ""),
                    "network_io": stats.get("NetIO", ""),
                    "restarts": state["restarts"],
                    "oom_killed": str(state["oom"]).lower(),
                    "temperature_c": "" if temp is None else f"{temp:.3f}",
                    "disk_available_bytes": disk_available,
                    "status": state["status"],
                })
                baseline_state = baseline[service]
                if state["restarts"] - baseline_state["restarts"] > args.max_restarts:
                    reasons.append(f"{service} restart threshold exceeded")
                    stop.set()
                if state["oom"]:
                    reasons.append(f"{service} reported OOMKilled")
                    stop.set()
                if state["status"] != "running":
                    reasons.append(f"{service} status is {state['status']}")
                    stop.set()
            output.flush()

            if temp is not None and temp > args.max_temp_c:
                reasons.append(f"host temperature {temp:.1f} C exceeded {args.max_temp_c:.1f} C")
                stop.set()
            if disk_available < args.min_disk_mib * 1024 * 1024:
                reasons.append("disk safety threshold crossed")
                stop.set()
            try:
                malformed = prom_scalar(args.prometheus_url, "sum(eventhorizon_exporter_malformed_messages_total)")
                gap = prom_scalar(
                    args.prometheus_url,
                    f'sum(total_connects{{server="{args.server_label}"}}) - '
                    f'sum(eventhorizon_completed_sessions_total{{protocol="{args.protocol}"}}) - '
                    f'sum(current_connected_clients{{server="{args.server_label}"}})',
                )
                if malformed > args.baseline_malformed:
                    reasons.append("malformed exporter telemetry increased")
                    stop.set()
                persistent_gap = persistent_gap + 1 if abs(gap) > 1e-9 else 0
                if persistent_gap >= 3:
                    reasons.append("lifecycle gap persisted for three monitor samples")
                    stop.set()
            except Exception as error:  # recorded as a stop because validation visibility was lost
                reasons.append(f"monitoring query failed: {type(error).__name__}")
                stop.set()

            if done.is_set():
                break
            time.sleep(1)
    csv_path.chmod(0o600)


def encode_remaining_length(value: int) -> bytes:
    output = bytearray()
    while True:
        byte = value % 128
        value //= 128
        if value:
            byte |= 0x80
        output.append(byte)
        if not value:
            return bytes(output)


def mqtt_connect_packet(index: int) -> bytes:
    client_id = f"ehv-{index}".encode()
    body = b"\x00\x04MQTT\x04\x02\x00\x05" + len(client_id).to_bytes(2, "big") + client_id
    return b"\x10" + encode_remaining_length(len(body)) + body


def mqtt_invalid_connect_packet(index: int) -> bytes:
    """Return a bounded CONNECT with the required reserved flag deliberately set."""
    client_id = f"ehv-{index}".encode()
    body = b"\x00\x04MQTT\x04\x03\x00\x05" + len(client_id).to_bytes(2, "big") + client_id
    return b"\x10" + encode_remaining_length(len(body)) + body


def mqtt_publish_packet() -> bytes:
    topic = b"validation/depth"
    payload = b"x"
    body = len(topic).to_bytes(2, "big") + topic + payload
    return b"\x30" + encode_remaining_length(len(body)) + body


def scenario_for(args, index: int) -> str:
    aliases = {
        "connect-disconnect": "depth0", "incomplete-input": "depth1",
        "one-line": "depth2", "multiple-lines": "depth3",
        "no-connect": "depth0", "connect-only": "depth1",
        "one-operation": "depth2", "multiple-operations": "depth3",
    }
    scenario = aliases.get(args.scenario, args.scenario)
    if scenario in ("matrix", "mixed"):
        return f"depth{index % 4}"
    if scenario not in {"depth0", "depth1", "depth2", "depth3"}:
        raise ValueError(f"unsupported scenario {args.scenario!r}")
    return scenario


def drain(sock: socket.socket, deadline: float = 0.6) -> None:
    end = time.monotonic() + deadline
    sock.settimeout(0.1)
    while time.monotonic() < end:
        try:
            if not sock.recv(4096):
                return
        except (socket.timeout, ConnectionResetError, BrokenPipeError):
            return


def run_client(args, index: int, stop: threading.Event) -> dict:
    scenario = scenario_for(args, index)
    row = {
        "session_index": index,
        "scenario": scenario,
        "connection_success": 0,
        "successful_completion": 0,
        "client_status": "not_attempted",
        "error": "",
    }
    if stop.is_set():
        row["client_status"] = "safety_stop"
        return row
    sock: socket.socket | None = None
    try:
        sock = socket.create_connection((args.target_host, args.target_port), timeout=3)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        row["connection_success"] = 1
        if args.protocol == "telnet":
            payloads = {
                "depth0": b"",
                "depth1": b"partial",
                "depth2": b"one-line\r\n",
                "depth3": b"one-line\nsecond-line\n",
            }
            payload = payloads[scenario]
            if payload:
                sock.sendall(payload)
            time.sleep(0.25)
            sock.shutdown(socket.SHUT_WR)
            drain(sock)
        else:
            if scenario != "depth0":
                sock.sendall(mqtt_connect_packet(index))
                time.sleep(0.08)
                sock.settimeout(0.15)
                try:
                    sock.recv(4096)
                except socket.timeout:
                    pass
                operation_count = {"depth1": 0, "depth2": 1, "depth3": 2}[scenario]
                for _ in range(operation_count):
                    sock.sendall(mqtt_publish_packet())
                    time.sleep(0.04)
                sock.sendall(b"\xe0\x00")
                drain(sock)
            else:
                if args.profile == "exact":
                    # Exercise a structurally complete but invalid CONNECT. The
                    # parser may answer, but it must not advance final depth.
                    sock.sendall(mqtt_invalid_connect_packet(index))
                    time.sleep(0.08)
                    sock.settimeout(0.15)
                    try:
                        sock.recv(4096)
                    except socket.timeout:
                        pass
                sock.shutdown(socket.SHUT_WR)
                drain(sock)
        row["successful_completion"] = 1
        row["client_status"] = "success"
    except Exception as error:
        row["client_status"] = "failure"
        row["error"] = type(error).__name__
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
    return row


def expected_depths(args) -> Counter:
    return Counter(scenario_for(args, index) for index in range(args.sessions))


def summary_table(before: dict[str, float], after: dict[str, float], args, expected: Counter, state_after: dict, reasons: list[str], client: dict) -> tuple[list[dict], dict]:
    protocol = args.protocol
    rows: list[dict] = []

    def add(
        name: str,
        key: str,
        expected_value: str,
        passed: bool | None = None,
        result_override: str | None = None,
    ):
        before_value = before.get(key, 0.0)
        after_value = after.get(key, 0.0)
        delta = after_value - before_value
        rows.append({
            "metric": name, "before": before_value, "after": after_value,
            "delta": delta, "expected": expected_value,
            "result": result_override or ("PASS" if passed is not False else "FAIL"),
        })

    requested = args.sessions
    add("connections", f"connections.{protocol}", str(requested), after[f"connections.{protocol}"] - before[f"connections.{protocol}"] == requested)
    add("completions", f"completions.{protocol}", str(requested), after[f"completions.{protocol}"] - before[f"completions.{protocol}"] == requested)
    add("active clients", f"active.{protocol}", "final 0", after[f"active.{protocol}"] == 0)
    add("lifecycle gap", f"lifecycle_gap.{protocol}", "final 0", abs(after[f"lifecycle_gap.{protocol}"]) < 1e-9)
    add("duration count", f"duration_count.{protocol}", str(requested), after[f"duration_count.{protocol}"] - before[f"duration_count.{protocol}"] == requested)
    add("histogram +Inf", f"duration_inf.{protocol}", "equals histogram count", after[f"duration_inf.{protocol}"] == after[f"duration_count.{protocol}"])
    add("malformed events", "malformed", "delta 0", after["malformed"] == before["malformed"])
    add("read outcomes", f"read_outcomes.{protocol}", "captured")
    add("write outcomes", f"write_outcomes.{protocol}", "captured")
    add("application RX", f"rx_bytes.{protocol}", ">= 0")
    add("application TX", f"tx_bytes.{protocol}", ">= 0")
    for depth in range(4):
        expected_count = expected[f"depth{depth}"]
        key = f"depth.{protocol}.{depth}"
        add(f"interaction depth {depth}", key, str(expected_count), after[key] - before[key] == expected_count)
    add("early disconnects", f"early_disconnect.{protocol}", "equals depth 0 delta",
        after[f"early_disconnect.{protocol}"] - before[f"early_disconnect.{protocol}"] == after[f"depth.{protocol}.0"] - before[f"depth.{protocol}.0"])
    for action in ACTIONS:
        key = f"action.{protocol}.{action}"
        if after[key] != before[key]:
            add(f"protocol action {action}", key, "captured")
    add("CPU cores (1m rate)", f"cpu_cores.{protocol}", "captured")
    add(
        "memory bytes",
        f"memory_bytes.{protocol}",
        "captured or UNSUPPORTED",
        result_override=None if args.memory_supported else "UNSUPPORTED",
    )
    add("network RX", f"network_rx_bytes.{protocol}", "captured")
    add("network TX", f"network_tx_bytes.{protocol}", "captured")

    depth_delta = sum(after[f"depth.{protocol}.{depth}"] - before[f"depth.{protocol}.{depth}"] for depth in range(4))
    completion_delta = after[f"completions.{protocol}"] - before[f"completions.{protocol}"]
    checks = {
        "client_failures_zero": client["client_failures"] == 0,
        "connections_match_requested": after[f"connections.{protocol}"] - before[f"connections.{protocol}"] == requested,
        "completions_match_requested": completion_delta == requested,
        "active_clients_settled": after[f"active.{protocol}"] == 0,
        "lifecycle_gap_zero": abs(after[f"lifecycle_gap.{protocol}"]) < 1e-9,
        "duration_count_matches": after[f"duration_count.{protocol}"] - before[f"duration_count.{protocol}"] == requested,
        "histogram_consistent": after[f"duration_inf.{protocol}"] == after[f"duration_count.{protocol}"],
        "depth_reconciles": depth_delta == completion_delta,
        "depth_distribution_matches": all(
            after[f"depth.{protocol}.{depth}"] - before[f"depth.{protocol}.{depth}"] == expected[f"depth{depth}"]
            for depth in range(4)
        ),
        "depth_zero_matches_early_disconnect": (
            after[f"depth.{protocol}.0"] - before[f"depth.{protocol}.0"]
            == after[f"early_disconnect.{protocol}"] - before[f"early_disconnect.{protocol}"]
        ),
        "malformed_unchanged": after["malformed"] == before["malformed"],
        "restart_threshold_respected": state_after["restarts"] - args.baseline_state[protocol + "_pit"]["restarts"] <= args.max_restarts,
        "oom_not_observed": not state_after["oom"],
        "failure_rate_within_limit": client["client_failures"] / requested <= args.max_failure_rate,
        "no_safety_stop": not reasons,
    }
    return rows, checks


def parse_args():
    parser = argparse.ArgumentParser()
    for argument in ("validation-id", "run-dir", "protocol", "profile", "scenario", "target-host", "target-host-category", "compose-project", "environment", "prometheus-url"):
        parser.add_argument(f"--{argument}", required=True)
    for argument in ("sessions", "concurrency", "settle-timeout", "max-restarts", "min-disk-mib", "target-port"):
        parser.add_argument(f"--{argument}", type=int, required=True)
    parser.add_argument("--max-temp-c", type=float, required=True)
    parser.add_argument("--max-failure-rate", type=float, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    args.run_dir = Path(args.run_dir).resolve()
    args.server_label = "Telnet" if args.protocol == "telnet" else "MQTT"
    args.run_dir.mkdir(parents=True, exist_ok=False) if not args.run_dir.exists() else None
    start_utc = utc_now()
    start_monotonic = time.monotonic()

    try:
        before = capture_metrics(args.prometheus_url)
    except Exception as error:
        print(f"FAIL: Prometheus baseline unavailable: {error}", file=sys.stderr)
        return 1
    write_metric_snapshot(args.run_dir / "prometheus-before.txt", before)

    baseline_state = {service: container_state(args.compose_project, service) for service in ("telnet_pit", "mqtt_pit")}
    args.baseline_state = baseline_state
    args.baseline_malformed = before["malformed"]
    for service, state in baseline_state.items():
        if state["status"] != "running":
            print(f"FAIL: {service} is not running in Compose project {args.compose_project}", file=sys.stderr)
            return 1

    images, limits = container_metadata(args.compose_project)
    memory_supported = (
        Path("/sys/fs/cgroup/cgroup.controllers").is_file()
        and "memory" in Path("/sys/fs/cgroup/cgroup.controllers").read_text(encoding="utf-8").split()
        and Path("/sys/fs/cgroup/memory.current").is_file()
    )
    args.memory_supported = memory_supported
    manifest = {
        "validation_id": args.validation_id,
        "validation_type": f"controlled_{args.profile}",
        "start_utc": start_utc,
        "end_utc": None,
        "duration_seconds": None,
        "git_commit": run(["git", "rev-parse", "HEAD"]).stdout.strip(),
        "host_architecture": platform.machine(),
        "host_identifier_category": args.environment,
        "target_identifier_category": args.target_host_category,
        "environment": args.environment,
        "protocol": args.protocol,
        "scenario": args.scenario,
        "scenario_distribution": dict(expected_depths(args)),
        "requested_sessions": args.sessions,
        "concurrency": args.concurrency,
        "settle_timeout_seconds": args.settle_timeout,
        "ramp_stage": 1 if args.sessions <= 10 else 2 if args.sessions <= 100 else 3,
        "prometheus_scrape_interval": "15s",
        "container_image_ids": images,
        "resource_limits": limits,
        "temperature_threshold_c": args.max_temp_c,
        "minimum_disk_mib": args.min_disk_mib,
        "memory_controller_status": "supported" if memory_supported else "unsupported",
    }
    manifest_path = args.run_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    manifest_path.chmod(0o600)

    monitor_done = threading.Event()
    safety_stop = threading.Event()
    reasons: list[str] = []
    monitor = threading.Thread(
        target=monitor_resources,
        args=(args, baseline_state, monitor_done, safety_stop, args.run_dir / "resource-snapshots.csv", reasons),
        daemon=True,
    )
    monitor.start()

    results: list[dict] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as executor:
        futures = [executor.submit(run_client, args, index, safety_stop) for index in range(args.sessions)]
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())
            failures_so_far = sum(item["client_status"] == "failure" for item in results)
            if failures_so_far / len(results) > args.max_failure_rate:
                if "client failure-rate threshold exceeded during the run" not in reasons:
                    reasons.append("client failure-rate threshold exceeded during the run")
                safety_stop.set()
    monitor_done.set()
    monitor.join(timeout=20)

    results.sort(key=lambda item: item["session_index"])
    csv_path = args.run_dir / "client-results.csv"
    with csv_path.open("w", encoding="utf-8", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=["session_index", "scenario", "connection_success", "successful_completion", "client_status", "error"])
        writer.writeheader()
        writer.writerows(results)
    csv_path.chmod(0o600)

    successful_connections = sum(row["connection_success"] for row in results)
    successful_completions = sum(row["successful_completion"] for row in results)
    client_failures = sum(row["client_status"] != "success" for row in results)
    settlement_deadline = time.monotonic() + args.settle_timeout
    settled = False
    while time.monotonic() < settlement_deadline:
        active = prom_scalar(args.prometheus_url, f'sum(current_connected_clients{{server="{args.server_label}"}})')
        completions = prom_scalar(args.prometheus_url, f'sum(eventhorizon_completed_sessions_total{{protocol="{args.protocol}"}})')
        if active == 0 and completions - before[f"completions.{args.protocol}"] >= successful_connections:
            settled = True
            break
        time.sleep(2)
    if not settled:
        reasons.append("active clients or completions did not settle before timeout")

    after = capture_metrics(args.prometheus_url)
    write_metric_snapshot(args.run_dir / "prometheus-after.txt", after)
    state_after = container_state(args.compose_project, args.protocol + "_pit")
    elapsed = time.monotonic() - start_monotonic
    client_summary = {
        "requested_sessions": args.sessions,
        "attempted_sessions": len(results),
        "successful_connections": successful_connections,
        "successful_completions": successful_completions,
        "client_failures": client_failures,
        "elapsed_seconds": round(elapsed, 3),
        "achieved_sessions_per_second": round(successful_completions / elapsed, 3) if elapsed else 0,
    }
    rows, checks = summary_table(before, after, args, expected_depths(args), state_after, reasons, client_summary)
    passed = all(checks.values())
    summary = {
        "validation_id": args.validation_id,
        "status": "PASS" if passed else "FAIL",
        "client": client_summary,
        "checks": checks,
        "safety_stop_reasons": sorted(set(reasons)),
        "metrics": rows,
        "memory_status": "PASS" if memory_supported and after[f"memory_bytes.{args.protocol}"] > 0 else "UNSUPPORTED",
    }
    summary_path = args.run_dir / "summary.json"
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    summary_path.chmod(0o600)

    md = [
        f"# Controlled validation {args.validation_id}", "",
        f"Status: **{summary['status']}**", "",
        "## Client result", "",
        "| Requested | Attempted | Connected | Client completions | Failures | Elapsed (s) | Sessions/s |",
        "| ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
        f"| {args.sessions} | {len(results)} | {successful_connections} | {successful_completions} | {client_failures} | {elapsed:.3f} | {client_summary['achieved_sessions_per_second']:.3f} |",
        "", "## Metric reconciliation", "",
        "| Metric | Before | After | Delta | Expected | Result |",
        "| ------ | -----: | ----: | ----: | -------- | ------ |",
    ]
    for row in rows:
        md.append(f"| {row['metric']} | {row['before']:.6g} | {row['after']:.6g} | {row['delta']:.6g} | {row['expected']} | {row['result']} |")
    md.extend(["", "## Safety", ""])
    md.append("No safety stop fired." if not reasons else "Safety stop/reconciliation reasons: " + "; ".join(sorted(set(reasons))))
    md.extend(["", f"Memory accounting: **{summary['memory_status']}**.", ""])
    (args.run_dir / "summary.md").write_text("\n".join(md), encoding="utf-8")
    (args.run_dir / "summary.md").chmod(0o600)

    manifest.update({
        "end_utc": utc_now(),
        "duration_seconds": round(elapsed, 3),
        "result": summary["status"],
    })
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
