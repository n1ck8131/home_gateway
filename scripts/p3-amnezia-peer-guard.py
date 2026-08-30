#!/usr/bin/env python3
"""Bounded, attested P3 server peer guard and read-only observer."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import shutil
import stat
import subprocess
import sys
import time
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from typing import Any, BinaryIO, TypeAlias

PUBLIC_PROTOCOL = {
    "schema": "home-gateway/p3-peer-guard-protocol/v2",
    "modes": ["attest", "reconcile", "guard", "client-observe", "emergency-rollback"],
    "guard_operations": ["admin", "guest"],
    "events": ["ready_for_ui", "candidate", "stopped"],
    "poll_seconds": 2,
    "stable_seconds": 5,
    "maximum_guard_seconds": 180,
}
MAX_REQUEST_BYTES = 65536
MAX_COMMAND_BYTES = 131072
MAX_PAYLOAD_BYTES = 262144
ALLOWED_EXECUTABLES = {
    "/usr/bin/docker",
    "/usr/bin/ss",
    "/usr/sbin/iptables-save",
    "/usr/sbin/ip6tables-save",
    "/usr/bin/systemctl",
    "/usr/bin/sha256sum",
    "/usr/bin/awg",
}
COMMON_REQUEST_KEYS = {
    "schema",
    "mode",
    "payload_sha256",
    "protocol_sha256",
    "manifest_sha256",
    "install_receipt_sha256",
    "nonce",
}
RECONCILE_KEYS = COMMON_REQUEST_KEYS | {
    "expected_container_identity_sha256",
    "expected_image_identity_sha256",
    "expected_udp_publication_sha256",
    "expected_listener_identity_sha256",
    "expected_host_policy_sha256",
    "expected_peer_count",
    "expected_peer_set_sha256",
    "expected_server_baseline_sha256",
    "expected_firewall_identity_sha256",
    "expected_ipv6_policy_sha256",
    "persistent_config_path",
    "metadata_path",
    "temporary_path",
}
GUARD_KEYS = RECONCILE_KEYS | {
    "operation",
    "candidate_class",
    "maximum_guard_seconds",
}
CLIENT_KEYS = COMMON_REQUEST_KEYS | {
    "previous_nonce_sha256",
    "selected_guest_fingerprint_sha256",
    "maximum_handshake_age_seconds",
}
ROLLBACK_PLAN_KEYS = {
    "payload_sha256",
    "protocol_sha256",
    "manifest_sha256",
    "install_receipt_sha256",
    "candidate_receipt_sha256",
    "candidate_fingerprint_sha256",
    "pre_peer_fingerprint_sha256",
    "post_peer_fingerprint_sha256",
    "baseline_peer_set_sha256",
    "persistent_config_path",
    "metadata_path",
    "temporary_path",
    "syncconf_path",
    "prepared_syncconf_sha256",
    "pre_persistent_config_sha256",
    "pre_live_peer_set_sha256",
    "pre_metadata_sha256",
    "pre_temporary_state_sha256",
    "pre_runtime_identity_sha256",
    "baseline_persistent_config_sha256",
    "baseline_metadata_sha256",
    "baseline_temporary_state_sha256",
    "baseline_runtime_identity_sha256",
}
ROLLBACK_KEYS = (
    COMMON_REQUEST_KEYS
    | ROLLBACK_PLAN_KEYS
    | {
        "rollback_plan_sha256",
        "confirmation",
    }
)
SERVER_IDENTITY_KEYS = (
    "container_count",
    "container_running",
    "container_identity_sha256",
    "image_identity_sha256",
    "container_restart_count",
    "udp_publication_count",
    "udp_publication_sha256",
    "public_listener_class_count",
    "listener_identity_sha256",
    "host_policy_loaded",
    "host_policy_sha256",
    "ipv6_non_mutation",
    "ipv6_policy_sha256",
    "peer_fingerprint_sha256",
    "persistent_peer_set_sha256",
    "live_peer_set_sha256",
    "metadata_peer_set_sha256",
    "candidate_leftover_count",
    "temporary_leftover_count",
    "atomic_leftover_count",
    "firewall_identity_sha256",
    "payload_sha256",
    "protocol_sha256",
)


@dataclass(frozen=True)
class CommandResult:
    exit_code: int
    stdout: bytes
    stderr: bytes


CommandRunner: TypeAlias = Callable[[Sequence[str], int, int], CommandResult]
FileReader: TypeAlias = Callable[[pathlib.Path, int], bytes]
FileLister: TypeAlias = Callable[[pathlib.Path], Sequence[pathlib.Path]]
Collector: TypeAlias = Callable[[dict[str, Any]], dict[str, Any]]
Clock: TypeAlias = Callable[[], float]
AtomicFilesystem: TypeAlias = Callable[[dict[str, Any]], dict[str, Any]]
SyncconfRunner: TypeAlias = Callable[[pathlib.Path], None]


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha(value: Any) -> str:
    if not isinstance(value, bytes):
        value = _canonical(value)
    return hashlib.sha256(value).hexdigest()


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def public_protocol_sha256() -> str:
    return _sha(PUBLIC_PROTOCOL)


def own_payload_sha256() -> str:
    path = pathlib.Path(__file__).absolute()
    before = os.lstat(path)
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_size <= 0
        or before.st_size > MAX_PAYLOAD_BYTES
    ):
        raise ValueError("peer guard payload is not one bounded regular file")
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise ValueError("peer guard payload identity changed")
        data = stream.read(MAX_PAYLOAD_BYTES + 1)
        if stream.read(1):
            raise ValueError("peer guard payload exceeds its bound")
    if len(data) != before.st_size:
        raise ValueError("peer guard payload identity changed")
    return _sha(data)


def read_exact_request(
    stream: BinaryIO, maximum_bytes: int = MAX_REQUEST_BYTES
) -> dict[str, Any]:
    data = stream.read(maximum_bytes + 1)
    if not data or len(data) > maximum_bytes:
        raise ValueError("request exceeds its byte limit")
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ValueError("request UTF-8 differs") from exc
    try:
        value = json.loads(text)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("request JSON differs") from exc
    if not isinstance(value, dict):
        raise TypeError("request JSON must be one object")
    return value


def _require_exact_keys(request: dict[str, Any], expected: set[str]) -> None:
    if set(request) != expected:
        raise ValueError("request schema differs")


def validate_request(mode: str, request: dict[str, Any]) -> dict[str, Any]:
    schemas = {
        "attest": COMMON_REQUEST_KEYS,
        "reconcile": RECONCILE_KEYS,
        "guard": GUARD_KEYS,
        "client-observe": CLIENT_KEYS,
        "emergency-rollback": ROLLBACK_KEYS,
    }
    if mode not in schemas:
        raise ValueError("request mode is unsupported")
    _require_exact_keys(request, schemas[mode])
    if request["schema"] != "home-gateway/p3-peer-guard-request/v2":
        raise ValueError("request schema differs")
    if request["mode"] != mode:
        raise ValueError("request mode differs")
    for name in (
        "payload_sha256",
        "protocol_sha256",
        "manifest_sha256",
        "install_receipt_sha256",
    ):
        if not _is_sha256(request[name]):
            raise ValueError(f"request {name} differs")
    if request["protocol_sha256"] != public_protocol_sha256():
        raise ValueError("request protocol identity differs")
    if request["payload_sha256"] != own_payload_sha256():
        raise ValueError("request payload identity differs")
    nonce = request["nonce"]
    if not _is_sha256(nonce):
        raise ValueError("request nonce differs")
    if mode in {"reconcile", "guard"}:
        for name in (
            "expected_container_identity_sha256",
            "expected_image_identity_sha256",
            "expected_udp_publication_sha256",
            "expected_listener_identity_sha256",
            "expected_host_policy_sha256",
            "expected_peer_set_sha256",
            "expected_server_baseline_sha256",
            "expected_firewall_identity_sha256",
            "expected_ipv6_policy_sha256",
        ):
            if not _is_sha256(request[name]):
                raise ValueError(f"request {name} differs")
        if (
            not isinstance(request["expected_peer_count"], int)
            or request["expected_peer_count"] < 0
            or request["expected_peer_count"] > 1024
        ):
            raise ValueError("request expected peer count differs")
    if mode == "guard":
        if request["operation"] not in {"admin", "guest"}:
            raise ValueError("guard operation differs")
        if request["candidate_class"] != request["operation"]:
            raise ValueError("guard candidate class differs")
        duration = request["maximum_guard_seconds"]
        if not isinstance(duration, int) or duration < 7 or duration > 180:
            raise ValueError("guard duration differs")
    if mode == "client-observe":
        for name in ("previous_nonce_sha256", "selected_guest_fingerprint_sha256"):
            if not _is_sha256(request[name]):
                raise ValueError(f"request {name} differs")
        if request["previous_nonce_sha256"] == _sha(nonce.encode("utf-8")):
            raise ValueError("replayed nonce is not allowed")
        maximum_age = request["maximum_handshake_age_seconds"]
        if not isinstance(maximum_age, int) or maximum_age < 1 or maximum_age > 300:
            raise ValueError("maximum handshake age differs")
    if mode == "emergency-rollback":
        for name in (
            "candidate_receipt_sha256",
            "rollback_plan_sha256",
            "candidate_fingerprint_sha256",
            "baseline_peer_set_sha256",
            "prepared_syncconf_sha256",
            "pre_persistent_config_sha256",
            "pre_live_peer_set_sha256",
            "pre_metadata_sha256",
            "pre_temporary_state_sha256",
            "pre_runtime_identity_sha256",
            "baseline_persistent_config_sha256",
            "baseline_metadata_sha256",
            "baseline_temporary_state_sha256",
            "baseline_runtime_identity_sha256",
        ):
            if not _is_sha256(request[name]):
                raise ValueError(f"request {name} differs")
        confirmation = request["confirmation"]
        if (
            not isinstance(confirmation, str)
            or len(confirmation) != len("P3-EMERGENCY-ROLLBACK-") + 16
            or not confirmation.startswith("P3-EMERGENCY-ROLLBACK-")
            or any(
                character not in "0123456789ABCDEF" for character in confirmation[-16:]
            )
        ):
            raise ValueError("emergency rollback confirmation differs")
        path_roots = {
            "persistent_config_path": pathlib.PurePosixPath("/opt/amnezia/awg"),
            "metadata_path": pathlib.PurePosixPath("/opt/amnezia/awg"),
            "temporary_path": pathlib.PurePosixPath("/run/home-gateway-p3-peer-guard"),
            "syncconf_path": pathlib.PurePosixPath("/run/home-gateway-p3-peer-guard"),
        }
        for name, root in path_roots.items():
            value = request[name]
            if not isinstance(value, str) or not value.startswith("/"):
                raise ValueError(f"emergency rollback {name} differs")
            path = pathlib.PurePosixPath(value)
            if (
                ".." in path.parts
                or pathlib.PurePosixPath(*path.parts[: len(root.parts)]) != root
            ):
                raise ValueError(f"emergency rollback {name} differs")
        pre_peers = request["pre_peer_fingerprint_sha256"]
        post_peers = request["post_peer_fingerprint_sha256"]
        candidate = request["candidate_fingerprint_sha256"]
        if (
            not isinstance(pre_peers, list)
            or not isinstance(post_peers, list)
            or any(not _is_sha256(peer) for peer in pre_peers + post_peers)
            or len(set(pre_peers)) != len(pre_peers)
            or len(set(post_peers)) != len(post_peers)
            or sorted(post_peers) != sorted(pre_peers + [candidate])
            or candidate in pre_peers
            or request["baseline_peer_set_sha256"] != _sha(sorted(pre_peers))
            or request["pre_live_peer_set_sha256"] != _sha(sorted(post_peers))
        ):
            raise ValueError("emergency rollback peer delta differs")
        plan_identity = {name: request[name] for name in ROLLBACK_PLAN_KEYS}
        expected_plan = _sha(plan_identity)
        if request["rollback_plan_sha256"] != expected_plan:
            raise ValueError("emergency rollback plan identity differs")
        expected_confirmation = "P3-EMERGENCY-ROLLBACK-" + expected_plan[:16].upper()
        if request["confirmation"] != expected_confirmation:
            raise ValueError("emergency rollback confirmation differs")
    return request


def _default_command_runner(
    arguments: Sequence[str], timeout_seconds: int, maximum_bytes: int
) -> CommandResult:
    try:
        result = subprocess.run(
            list(arguments),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise ValueError("allowlisted command timeout") from exc
    stdout = result.stdout[: maximum_bytes + 1]
    stderr = result.stderr[: maximum_bytes + 1]
    return CommandResult(result.returncode, stdout, stderr)


def run_checked_command(
    arguments: Sequence[str],
    *,
    runner: CommandRunner = _default_command_runner,
    timeout_seconds: int = 10,
    maximum_bytes: int = MAX_COMMAND_BYTES,
) -> bytes:
    if not arguments or arguments[0] not in ALLOWED_EXECUTABLES:
        raise ValueError("command executable is not allowlisted")
    if timeout_seconds < 1 or timeout_seconds > 10:
        raise ValueError("command timeout differs")
    if maximum_bytes < 1 or maximum_bytes > MAX_COMMAND_BYTES:
        raise ValueError("command output bound differs")
    try:
        result = runner(tuple(arguments), timeout_seconds, maximum_bytes)
    except TimeoutError as exc:
        raise ValueError("allowlisted command timeout") from exc
    if result.exit_code != 0:
        raise ValueError("allowlisted command exit differs")
    if result.stderr:
        raise ValueError("allowlisted command emitted stderr")
    if len(result.stdout) > maximum_bytes:
        raise ValueError("allowlisted command output exceeds bound")
    return result.stdout


def _read_utf8_lines(data: bytes, label: str) -> list[str]:
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{label} UTF-8 differs") from exc
    return [line for line in text.splitlines() if line]


def collect_server_snapshot(
    request: dict[str, Any],
    runner: CommandRunner = _default_command_runner,
    reader: FileReader = lambda path, maximum: _read_atomic_file(path, maximum),
    lister: FileLister = lambda path: tuple(path.iterdir()),
) -> dict[str, Any]:
    docker_rows = _read_utf8_lines(
        run_checked_command(
            [
                "/usr/bin/docker",
                "ps",
                "--filter",
                "status=running",
                "--format",
                "{{.ID}}|{{.Image}}|{{.Ports}}",
            ],
            runner=runner,
        ),
        "container observation",
    )
    if len(docker_rows) != 1:
        raise ValueError("container count differs")
    fields = docker_rows[0].split("|", 2)
    if len(fields) != 3:
        raise ValueError("container observation differs")
    container_id, image, ports = fields
    inspect_bytes = run_checked_command(
        [
            "/usr/bin/docker",
            "inspect",
            "--format",
            "{{.RestartCount}}|{{.Image}}",
            container_id,
        ],
        runner=runner,
    )
    inspect_fields = (
        inspect_bytes.decode("utf-8", errors="strict").strip().split("|", 1)
    )
    if len(inspect_fields) != 2 or not inspect_fields[0].isdigit():
        raise ValueError("container inspect observation differs")
    listener_bytes = run_checked_command(["/usr/bin/ss", "-H", "-lntu"], runner=runner)
    ipv4_policy = run_checked_command(["/usr/sbin/iptables-save"], runner=runner)
    ipv6_policy = run_checked_command(["/usr/sbin/ip6tables-save"], runner=runner)
    policy_loaded = (
        run_checked_command(
            ["/usr/bin/systemctl", "is-active", "netfilter-persistent.service"],
            runner=runner,
        )
        .decode("utf-8", errors="strict")
        .strip()
        == "active"
    )
    live_peer_lines = _read_utf8_lines(
        run_checked_command(
            ["/usr/bin/awg", "show", "all", "public-keys"], runner=runner
        ),
        "peer observation",
    )
    live_peers = sorted(_sha(line.encode("utf-8")) for line in live_peer_lines)
    config_path = pathlib.Path(request["persistent_config_path"])
    metadata_path = pathlib.Path(request["metadata_path"])
    temporary_path = pathlib.Path(request["temporary_path"])
    config_text = reader(config_path, 1048576).decode("utf-8", errors="strict")
    _, blocks = _config_peer_blocks(config_text)
    persistent_peers = sorted(
        fingerprint
        for fingerprint in (_block_fingerprint(block) for block in blocks)
        if fingerprint is not None
    )
    metadata_value = json.loads(
        reader(metadata_path, 1048576).decode("utf-8", errors="strict")
    )
    rows, _ = _metadata_rows(metadata_value)
    metadata_peers = sorted(_row_fingerprint(row) for row in rows)
    peer_classes: dict[str, str] = {}
    for row in rows:
        fingerprint = _row_fingerprint(row)
        role = row.get("role")
        if role not in {"baseline", "admin", "guest"} or fingerprint in peer_classes:
            raise ValueError("peer metadata classification differs")
        peer_classes[fingerprint] = role
    leftovers = [path.name for path in lister(temporary_path.parent)]
    candidate_leftovers = sum("candidate" in name for name in leftovers)
    atomic_leftovers = sum(".p3-next-" in name for name in leftovers)
    temporary_leftovers = int(temporary_path.name in leftovers)
    firewall_identity = _sha(ipv4_policy + b"\0" + ipv6_policy)
    return {
        "container_count": 1,
        "container_running": True,
        "container_identity_sha256": _sha(container_id.encode("utf-8")),
        "image_identity_sha256": _sha((image + "|" + inspect_fields[1]).encode()),
        "container_restart_count": int(inspect_fields[0]),
        "udp_publication_count": int("38556" in ports and "udp" in ports.lower()),
        "udp_publication_sha256": _sha(ports.encode("utf-8")),
        "public_listener_class_count": len(
            _read_utf8_lines(listener_bytes, "listener")
        ),
        "listener_identity_sha256": _sha(listener_bytes),
        "host_policy_loaded": policy_loaded,
        "host_policy_sha256": _sha(ipv4_policy),
        "ipv6_non_mutation": _sha(ipv6_policy)
        == request["expected_ipv6_policy_sha256"],
        "ipv6_policy_sha256": _sha(ipv6_policy),
        "peer_fingerprint_sha256": live_peers,
        "peer_classes": peer_classes,
        "persistent_peer_set_sha256": _sha(persistent_peers),
        "live_peer_set_sha256": _sha(live_peers),
        "metadata_peer_set_sha256": _sha(metadata_peers),
        "candidate_leftover_count": candidate_leftovers,
        "temporary_leftover_count": temporary_leftovers,
        "atomic_leftover_count": atomic_leftovers,
        "firewall_identity_sha256": firewall_identity,
        "payload_sha256": own_payload_sha256(),
        "protocol_sha256": public_protocol_sha256(),
    }


def _server_identity(snapshot: dict[str, Any]) -> str:
    try:
        selected = {name: snapshot[name] for name in SERVER_IDENTITY_KEYS}
    except KeyError as exc:
        raise ValueError("server snapshot schema differs") from exc
    return _sha(selected)


def _require_snapshot_hash(snapshot: dict[str, Any], name: str) -> str:
    value = snapshot.get(name)
    if not _is_sha256(value):
        raise ValueError(f"server {name} differs")
    return value


def _validate_baseline_snapshot(
    request: dict[str, Any], snapshot: dict[str, Any]
) -> dict[str, Any]:
    if snapshot.get("container_count") != 1:
        raise ValueError("container count differs")
    if snapshot.get("container_running") is not True:
        raise ValueError("container running state differs")
    comparisons = (
        (
            "container_identity_sha256",
            "expected_container_identity_sha256",
            "container identity",
        ),
        ("image_identity_sha256", "expected_image_identity_sha256", "image identity"),
        (
            "udp_publication_sha256",
            "expected_udp_publication_sha256",
            "UDP publication",
        ),
        (
            "listener_identity_sha256",
            "expected_listener_identity_sha256",
            "listener identity",
        ),
        ("host_policy_sha256", "expected_host_policy_sha256", "host policy"),
    )
    for actual_name, expected_name, label in comparisons:
        if _require_snapshot_hash(snapshot, actual_name) != request[expected_name]:
            raise ValueError(f"{label} differs")
    if snapshot.get("udp_publication_count") != 1:
        raise ValueError("UDP publication count differs")
    if not isinstance(snapshot.get("public_listener_class_count"), int):
        raise TypeError("listener class count differs")
    if snapshot.get("host_policy_loaded") is not True:
        raise ValueError("host policy loaded state differs")
    if snapshot.get("ipv6_non_mutation") is not True:
        raise ValueError("IPv6 non-mutation state differs")
    if snapshot.get("ipv6_policy_sha256") != request["expected_ipv6_policy_sha256"]:
        raise ValueError("IPv6 policy identity differs")
    if (
        snapshot.get("firewall_identity_sha256")
        != request["expected_firewall_identity_sha256"]
    ):
        raise ValueError("firewall identity differs")
    peers = snapshot.get("peer_fingerprint_sha256")
    if not isinstance(peers, list) or any(not _is_sha256(peer) for peer in peers):
        raise ValueError("peer set schema differs")
    expected_set = _sha(sorted(peers))
    if (
        len(peers) != request["expected_peer_count"]
        or expected_set != request["expected_peer_set_sha256"]
    ):
        raise ValueError("peer set differs")
    for name in (
        "persistent_peer_set_sha256",
        "live_peer_set_sha256",
        "metadata_peer_set_sha256",
    ):
        if snapshot.get(name) != expected_set:
            raise ValueError("peer set convergence differs")
    for name in (
        "candidate_leftover_count",
        "temporary_leftover_count",
        "atomic_leftover_count",
    ):
        if snapshot.get(name) != 0:
            raise ValueError("leftover count differs")
    if snapshot.get("payload_sha256") != request["payload_sha256"]:
        raise ValueError("payload identity differs")
    if snapshot.get("protocol_sha256") != request["protocol_sha256"]:
        raise ValueError("protocol identity differs")
    identity = _server_identity(snapshot)
    if identity != request["expected_server_baseline_sha256"]:
        raise ValueError("server baseline identity differs")
    return snapshot


def _reconcile_receipt(
    request: dict[str, Any], snapshot: dict[str, Any]
) -> dict[str, Any]:
    peers = snapshot["peer_fingerprint_sha256"]
    return {
        "schema": "home-gateway/p3-peer-reconcile-receipt/v2",
        "payload_sha256": request["payload_sha256"],
        "protocol_sha256": request["protocol_sha256"],
        "manifest_sha256": request["manifest_sha256"],
        "install_receipt_sha256": request["install_receipt_sha256"],
        "nonce_sha256": _sha(request["nonce"].encode()),
        "container_count": 1,
        "container_running": True,
        "container_identity_sha256": snapshot["container_identity_sha256"],
        "image_identity_sha256": snapshot["image_identity_sha256"],
        "container_restart_count_sha256": _sha(
            str(snapshot["container_restart_count"]).encode()
        ),
        "udp_publication_count": 1,
        "udp_publication_sha256": snapshot["udp_publication_sha256"],
        "public_listener_class_count": snapshot["public_listener_class_count"],
        "listener_identity_sha256": snapshot["listener_identity_sha256"],
        "host_policy_loaded": True,
        "host_policy_sha256": snapshot["host_policy_sha256"],
        "ipv6_non_mutation": True,
        "peer_count": len(peers),
        "peer_set_sha256": _sha(sorted(peers)),
        "candidate_leftover_count": 0,
        "temporary_leftover_count": 0,
        "atomic_leftover_count": 0,
        "server_baseline_sha256": _server_identity(snapshot),
    }


def run_reconcile(request: dict[str, Any], collector: Collector) -> dict[str, Any]:
    validate_request("reconcile", request)
    snapshot = collector(dict(request))
    _validate_baseline_snapshot(request, snapshot)
    return _reconcile_receipt(request, snapshot)


def _clock_sleep(clock: Clock, seconds: float) -> None:
    sleeper = getattr(clock, "sleep", None)
    if sleeper is None:
        time.sleep(seconds)
    else:
        sleeper(seconds)


def _bounded_sleep(clock: Clock, deadline: float, seconds: float) -> bool:
    remaining = deadline - clock()
    if remaining <= 0:
        return False
    if remaining < seconds:
        _clock_sleep(clock, remaining)
        return False
    _clock_sleep(clock, seconds)
    return clock() < deadline or seconds == 0


def _stopped_event(request: dict[str, Any], reason: str) -> dict[str, Any]:
    return {
        "event": "stopped",
        "schema": "home-gateway/p3-peer-guard-event/v2",
        "operation": request["operation"],
        "payload_sha256": request["payload_sha256"],
        "protocol_sha256": request["protocol_sha256"],
        "nonce_sha256": _sha(request["nonce"].encode()),
        "reason": reason,
    }


def _candidate_state(
    baseline: dict[str, Any], snapshot: dict[str, Any], operation: str
) -> tuple[str, str | None]:
    baseline_peers = set(baseline["peer_fingerprint_sha256"])
    current_peers = set(snapshot.get("peer_fingerprint_sha256", []))
    delta = current_peers - baseline_peers
    if baseline_peers - current_peers or len(delta) > 1:
        return "invalid", None
    expected_set = _sha(sorted(current_peers))
    convergence = (
        snapshot.get("persistent_peer_set_sha256"),
        snapshot.get("live_peer_set_sha256"),
        snapshot.get("metadata_peer_set_sha256"),
    )
    if len(set(convergence)) != 1 or convergence[0] != expected_set:
        return "wait", None
    immutable = (
        "container_identity_sha256",
        "image_identity_sha256",
        "udp_publication_sha256",
        "listener_identity_sha256",
        "host_policy_sha256",
        "ipv6_non_mutation",
        "firewall_identity_sha256",
    )
    if any(snapshot.get(name) != baseline.get(name) for name in immutable):
        return "invalid", None
    if snapshot.get("container_restart_count") != baseline.get(
        "container_restart_count"
    ):
        return "invalid", None
    if any(
        snapshot.get(name) != 0
        for name in (
            "candidate_leftover_count",
            "temporary_leftover_count",
            "atomic_leftover_count",
        )
    ):
        return "invalid", None
    if not delta:
        return "wait", None
    candidate = next(iter(delta))
    classes = snapshot.get("peer_classes")
    if not isinstance(classes, dict) or classes.get(candidate) != operation:
        return "invalid", None
    return "candidate", candidate


def _guard_snapshot_identity(snapshot: dict[str, Any]) -> str:
    selected = {name: snapshot.get(name) for name in SERVER_IDENTITY_KEYS}
    selected["peer_classes"] = snapshot.get("peer_classes")
    return _sha(selected)


def run_guard(
    operation: str,
    request: dict[str, Any],
    collector: Collector,
    clock: Clock,
) -> Iterator[dict[str, Any]]:
    validate_request("guard", request)
    if request["operation"] != operation:
        raise ValueError("guard operation binding differs")
    baseline = collector({**request, "phase": "baseline"})
    _validate_baseline_snapshot(request, baseline)
    reconcile = _reconcile_receipt(request, baseline)
    yield {
        "event": "ready_for_ui",
        "schema": "home-gateway/p3-peer-guard-event/v2",
        "operation": operation,
        "payload_sha256": request["payload_sha256"],
        "protocol_sha256": request["protocol_sha256"],
        "nonce_sha256": _sha(request["nonce"].encode()),
        "pre_peer_count": len(baseline["peer_fingerprint_sha256"]),
        "pre_peer_set_sha256": _sha(sorted(baseline["peer_fingerprint_sha256"])),
        "reconcile_sha256": _sha(reconcile),
    }
    deadline = clock() + request["maximum_guard_seconds"]
    while True:
        if not _bounded_sleep(clock, deadline, PUBLIC_PROTOCOL["poll_seconds"]):
            yield _stopped_event(request, "TIMEOUT")
            return
        first = collector({**request, "phase": "candidate"})
        state, candidate = _candidate_state(baseline, first, operation)
        if state == "invalid":
            yield _stopped_event(request, "DELTA_INVALID")
            return
        if state == "wait":
            continue
        if not _bounded_sleep(clock, deadline, PUBLIC_PROTOCOL["stable_seconds"]):
            yield _stopped_event(request, "TIMEOUT")
            return
        second = collector({**request, "phase": "stability"})
        second_state, second_candidate = _candidate_state(baseline, second, operation)
        if second_state == "invalid":
            yield _stopped_event(request, "DELTA_INVALID")
            return
        if (
            second_state != "candidate"
            or second_candidate != candidate
            or _guard_snapshot_identity(second) != _guard_snapshot_identity(first)
        ):
            continue
        assert candidate is not None
        post_set = _sha(sorted(second["peer_fingerprint_sha256"]))
        yield {
            "event": "candidate",
            "schema": "home-gateway/p3-peer-guard-event/v2",
            "operation": operation,
            "payload_sha256": request["payload_sha256"],
            "protocol_sha256": request["protocol_sha256"],
            "nonce_sha256": _sha(request["nonce"].encode()),
            "candidate_count": 1,
            "candidate_fingerprint_sha256": candidate,
            "pre_peer_set_sha256": _sha(sorted(baseline["peer_fingerprint_sha256"])),
            "post_peer_set_sha256": post_set,
            "persistent_live_metadata_equal": True,
            "semantic_transition_count": 1,
            "container_restart_delta": 0,
            "firewall_equal": True,
            "listeners_equal": True,
            "official_ui_rollback_ready": True,
            "emergency_rollback_ready": True,
        }
        return


def _validate_client_state(
    state: dict[str, Any], request: dict[str, Any], label: str
) -> str:
    if (
        state.get("selected_guest_fingerprint_sha256")
        != request["selected_guest_fingerprint_sha256"]
        or state.get("selected_guest_match") is not True
    ):
        raise ValueError("selected Guest identity differs")
    age = state.get("handshake_age_seconds")
    if (
        not isinstance(age, (int, float))
        or age < 0
        or age > request["maximum_handshake_age_seconds"]
    ):
        raise ValueError("handshake freshness differs")
    counters = state.get("counter_state")
    if (
        not isinstance(counters, dict)
        or not counters
        or any(not isinstance(value, int) or value < 0 for value in counters.values())
    ):
        raise ValueError(f"{label} counter state differs")
    return _sha(counters)


def run_client_observe(
    request: dict[str, Any], collector: Collector, clock: Clock
) -> dict[str, Any]:
    validate_request("client-observe", request)
    observation_request = {
        "mode": "client-observe",
        "selected_guest_fingerprint_sha256": request[
            "selected_guest_fingerprint_sha256"
        ],
        "maximum_handshake_age_seconds": request["maximum_handshake_age_seconds"],
    }
    before = collector({**observation_request, "phase": "before"})
    before_hash = _validate_client_state(before, request, "before")
    _clock_sleep(clock, 10)
    after = collector({**observation_request, "phase": "after"})
    after_hash = _validate_client_state(after, request, "after")
    before_counters = before["counter_state"]
    after_counters = after["counter_state"]
    if (
        set(before_counters) != set(after_counters)
        or any(after_counters[name] < before_counters[name] for name in before_counters)
        or not any(
            after_counters[name] > before_counters[name] for name in before_counters
        )
    ):
        raise ValueError("counter traffic delta differs")
    return {
        "schema": "home-gateway/p3-peer-client-observe/v2",
        "payload_sha256": request["payload_sha256"],
        "protocol_sha256": request["protocol_sha256"],
        "nonce_sha256": _sha(request["nonce"].encode()),
        "selected_guest_match": True,
        "handshake_fresh": True,
        "before_counter_sha256": before_hash,
        "after_counter_sha256": after_hash,
        "traffic_delta": True,
        "observation_duration_seconds": 10,
    }


ROLLBACK_OBSERVATION_KEYS = {
    "schema",
    "candidate_receipt_sha256",
    "candidate_fingerprint_sha256",
    "peer_fingerprint_sha256",
    "peer_set_sha256",
    "persistent_config_sha256",
    "live_peer_set_sha256",
    "metadata_sha256",
    "temporary_state_sha256",
    "runtime_identity_sha256",
    "prepared_syncconf_sha256",
}


def rollback_expected_observation(
    request: dict[str, Any], *, phase: str
) -> dict[str, Any]:
    if phase == "pre":
        peers = request["post_peer_fingerprint_sha256"]
        values = (
            request["pre_persistent_config_sha256"],
            request["pre_live_peer_set_sha256"],
            request["pre_metadata_sha256"],
            request["pre_temporary_state_sha256"],
            request["pre_runtime_identity_sha256"],
        )
    elif phase == "baseline":
        peers = request["pre_peer_fingerprint_sha256"]
        values = (
            request["baseline_persistent_config_sha256"],
            request["baseline_peer_set_sha256"],
            request["baseline_metadata_sha256"],
            request["baseline_temporary_state_sha256"],
            request["baseline_runtime_identity_sha256"],
        )
    else:
        raise ValueError("rollback observation phase differs")
    return {
        "schema": "home-gateway/p3-peer-rollback-observation/v2",
        "candidate_receipt_sha256": request["candidate_receipt_sha256"],
        "candidate_fingerprint_sha256": request["candidate_fingerprint_sha256"],
        "peer_fingerprint_sha256": sorted(peers),
        "peer_set_sha256": _sha(sorted(peers)),
        "persistent_config_sha256": values[0],
        "live_peer_set_sha256": values[1],
        "metadata_sha256": values[2],
        "temporary_state_sha256": values[3],
        "runtime_identity_sha256": values[4],
        "prepared_syncconf_sha256": request["prepared_syncconf_sha256"],
    }


def _require_rollback_observation(
    actual: dict[str, Any], expected: dict[str, Any], label: str
) -> None:
    if not isinstance(actual, dict):
        raise TypeError(f"emergency rollback {label} observation differs")
    _require_exact_keys(actual, ROLLBACK_OBSERVATION_KEYS)
    if actual != expected:
        raise ValueError(f"emergency rollback {label} observation differs")


def run_emergency_rollback(
    request: dict[str, Any],
    filesystem: AtomicFilesystem,
    syncconf: SyncconfRunner,
) -> dict[str, Any]:
    validate_request("emergency-rollback", request)
    candidate = request["candidate_fingerprint_sha256"]
    file_context = {name: request[name] for name in ROLLBACK_PLAN_KEYS}
    inspected = filesystem({"action": "inspect", **file_context})
    _require_rollback_observation(
        inspected, rollback_expected_observation(request, phase="pre"), "pre"
    )
    removed = filesystem({"action": "remove", **file_context})
    if (
        not isinstance(removed, dict)
        or set(removed) != {"removed", "recovery_state"}
        or removed.get("removed") is not True
        or not isinstance(removed.get("recovery_state"), str)
        or not removed["recovery_state"]
    ):
        raise RuntimeError("candidate removal failed")
    try:
        syncconf(pathlib.Path(request["syncconf_path"]))
        verified = filesystem({"action": "verify", **file_context})
        _require_rollback_observation(
            verified,
            rollback_expected_observation(request, phase="baseline"),
            "baseline",
        )
        cleaned = filesystem(
            {
                "action": "cleanup",
                **file_context,
                "recovery_state": removed["recovery_state"],
            }
        )
        if cleaned != {"cleaned": True}:
            raise RuntimeError("emergency rollback recovery cleanup differs")
    except Exception as exc:
        recovered = filesystem(
            {
                "action": "recover",
                **file_context,
                "recovery_state": removed["recovery_state"],
            }
        )
        if (
            not isinstance(recovered, dict)
            or set(recovered) != {"recovered", "recovery_syncconf_path"}
            or recovered.get("recovered") is not True
        ):
            raise RuntimeError("emergency rollback recovery failed") from exc
        syncconf(pathlib.Path(recovered["recovery_syncconf_path"]))
        recovery_verified = filesystem({"action": "verify-recovery", **file_context})
        _require_rollback_observation(
            recovery_verified,
            rollback_expected_observation(request, phase="pre"),
            "recovery",
        )
        raise RuntimeError("emergency rollback failed atomically") from exc
    return {
        "schema": "home-gateway/p3-peer-emergency-rollback/v2",
        "payload_sha256": request["payload_sha256"],
        "protocol_sha256": request["protocol_sha256"],
        "manifest_sha256": request["manifest_sha256"],
        "install_receipt_sha256": request["install_receipt_sha256"],
        "candidate_receipt_sha256": request["candidate_receipt_sha256"],
        "rollback_plan_sha256": request["rollback_plan_sha256"],
        "candidate_fingerprint_sha256": candidate,
        "one_syncconf": True,
        "restored": True,
        "temporary_leftover_count": 0,
    }


def _attest(request: dict[str, Any]) -> dict[str, Any]:
    validate_request("attest", request)
    payload = own_payload_sha256()
    if request["payload_sha256"] != payload:
        raise ValueError("peer guard payload identity differs")
    return {
        "schema": "home-gateway/p3-peer-attest-receipt/v2",
        "payload_sha256": payload,
        "protocol_sha256": public_protocol_sha256(),
        "nonce_sha256": _sha(request["nonce"].encode()),
    }


def _self_test() -> None:
    assert public_protocol_sha256() == _sha(PUBLIC_PROTOCOL)
    assert _is_sha256(public_protocol_sha256())
    assert set(PUBLIC_PROTOCOL["modes"]) == {
        "attest",
        "reconcile",
        "guard",
        "client-observe",
        "emergency-rollback",
    }


def _system_collector(request: dict[str, Any]) -> dict[str, Any]:
    return collect_server_snapshot(request)


def _system_client_collector(request: dict[str, Any]) -> dict[str, Any]:
    selected = request["selected_guest_fingerprint_sha256"]
    handshake_lines = _read_utf8_lines(
        run_checked_command(["/usr/bin/awg", "show", "all", "latest-handshakes"]),
        "client handshake observation",
    )
    transfer_lines = _read_utf8_lines(
        run_checked_command(["/usr/bin/awg", "show", "all", "transfer"]),
        "client counter observation",
    )
    handshakes: dict[str, int] = {}
    for line in handshake_lines:
        fields = line.split("\t")
        if len(fields) != 3 or not fields[2].isdigit():
            raise ValueError("client handshake observation differs")
        fingerprint = _sha(fields[1].encode("utf-8"))
        if fingerprint in handshakes:
            raise ValueError("client handshake observation is ambiguous")
        handshakes[fingerprint] = int(fields[2])
    counters: dict[str, dict[str, int]] = {}
    for line in transfer_lines:
        fields = line.split("\t")
        if len(fields) != 4 or not fields[2].isdigit() or not fields[3].isdigit():
            raise ValueError("client counter observation differs")
        fingerprint = _sha(fields[1].encode("utf-8"))
        if fingerprint in counters:
            raise ValueError("client counter observation is ambiguous")
        counters[fingerprint] = {"rx": int(fields[2]), "tx": int(fields[3])}
    if selected not in handshakes or selected not in counters:
        raise ValueError("selected Guest identity differs")
    epoch = handshakes[selected]
    age = max(0, int(time.time()) - epoch) if epoch > 0 else 2**31 - 1
    return {
        "selected_guest_fingerprint_sha256": selected,
        "selected_guest_match": True,
        "handshake_age_seconds": age,
        "counter_state": counters[selected],
    }


def _read_atomic_file(path: pathlib.Path, maximum_bytes: int) -> bytes:
    before = path.lstat()
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_size <= 0
        or before.st_size > maximum_bytes
    ):
        raise ValueError("emergency rollback file differs")
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise ValueError("emergency rollback file identity changed")
        data = stream.read(maximum_bytes + 1)
    if len(data) != before.st_size or len(data) > maximum_bytes:
        raise ValueError("emergency rollback file size differs")
    return data


def _config_peer_blocks(text: str) -> tuple[list[str], list[list[str]]]:
    prefix: list[str] = []
    blocks: list[list[str]] = []
    current: list[str] | None = None
    for line in text.splitlines(keepends=True):
        if line.strip() == "[Peer]":
            current = [line]
            blocks.append(current)
        elif current is None:
            prefix.append(line)
        else:
            current.append(line)
    return prefix, blocks


def _block_fingerprint(block: list[str]) -> str | None:
    values = []
    for line in block:
        if line.lstrip().startswith("PublicKey") and "=" in line:
            values.append(line.split("=", 1)[1].strip())
    if len(values) != 1:
        return None
    return _sha(values[0].encode("utf-8"))


def _metadata_rows(value: Any) -> tuple[list[dict[str, Any]], str]:
    if isinstance(value, list):
        rows = value
        shape = "list"
    elif (
        isinstance(value, dict)
        and set(value) == {"peers"}
        and isinstance(value["peers"], list)
    ):
        rows = value["peers"]
        shape = "object"
    else:
        raise ValueError("emergency rollback metadata schema differs")
    if any(not isinstance(row, dict) or "public_key" not in row for row in rows):
        raise ValueError("emergency rollback metadata row differs")
    return rows, shape


def _row_fingerprint(row: dict[str, Any]) -> str:
    key = row.get("public_key")
    if not isinstance(key, str) or not key:
        raise ValueError("emergency rollback metadata key differs")
    return _sha(key.encode("utf-8"))


def _atomic_replace(path: pathlib.Path, data: bytes) -> None:
    current = path.lstat()
    temporary = path.with_name(path.name + ".p3-next-" + os.urandom(16).hex())
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        stat.S_IMODE(current.st_mode),
    )
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chown(temporary, current.st_uid, current.st_gid)
        os.replace(temporary, path)
        directory_descriptor = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


_RECOVERY_STATES: dict[str, dict[str, pathlib.Path | None]] = {}


def _rollback_runtime_identity() -> str:
    observations = []
    for arguments in (
        [
            "/usr/bin/docker",
            "ps",
            "--filter",
            "status=running",
            "--format",
            "{{.ID}}|{{.Image}}|{{.Ports}}",
        ],
        ["/usr/bin/ss", "-H", "-lntu"],
        ["/usr/sbin/iptables-save"],
        ["/usr/sbin/ip6tables-save"],
        ["/usr/bin/systemctl", "is-active", "netfilter-persistent.service"],
    ):
        observations.append(_sha(run_checked_command(arguments)))
    return _sha(observations)


def _system_rollback_observation(action: dict[str, Any]) -> dict[str, Any]:
    config_path = pathlib.Path(action["persistent_config_path"])
    metadata_path = pathlib.Path(action["metadata_path"])
    temporary_path = pathlib.Path(action["temporary_path"])
    syncconf_path = pathlib.Path(action["syncconf_path"])
    live_keys = _read_utf8_lines(
        run_checked_command(["/usr/bin/awg", "show", "all", "public-keys"]),
        "rollback live peer observation",
    )
    peers = sorted(_sha(key.encode("utf-8")) for key in live_keys)
    temporary_state = (
        _sha(_read_atomic_file(temporary_path, 65536))
        if temporary_path.exists()
        else _sha(b"ABSENT")
    )
    return {
        "schema": "home-gateway/p3-peer-rollback-observation/v2",
        "candidate_receipt_sha256": action["candidate_receipt_sha256"],
        "candidate_fingerprint_sha256": action["candidate_fingerprint_sha256"],
        "peer_fingerprint_sha256": peers,
        "peer_set_sha256": _sha(peers),
        "persistent_config_sha256": _sha(_read_atomic_file(config_path, 1048576)),
        "live_peer_set_sha256": _sha(peers),
        "metadata_sha256": _sha(_read_atomic_file(metadata_path, 1048576)),
        "temporary_state_sha256": temporary_state,
        "runtime_identity_sha256": _rollback_runtime_identity(),
        "prepared_syncconf_sha256": _sha(_read_atomic_file(syncconf_path, 1048576)),
    }


def _backup_exact_file(path: pathlib.Path, backup: pathlib.Path) -> None:
    descriptor = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(descriptor)
    try:
        shutil.copy2(path, backup)
    except Exception:
        backup.unlink(missing_ok=True)
        raise


def _system_atomic_filesystem(action: dict[str, Any]) -> dict[str, Any]:
    candidate = action["candidate_fingerprint_sha256"]
    config_path = pathlib.Path(action["persistent_config_path"])
    metadata_path = pathlib.Path(action["metadata_path"])
    temporary_path = pathlib.Path(action["temporary_path"])
    if action["action"] in {"inspect", "verify", "verify-recovery"}:
        return _system_rollback_observation(action)
    if action["action"] == "cleanup":
        state = _RECOVERY_STATES.pop(action["recovery_state"], None)
        if state is None:
            raise ValueError("emergency rollback recovery state differs")
        for backup in state.values():
            if backup is not None:
                backup.unlink(missing_ok=True)
        return {"cleaned": True}
    if action["action"] == "recover":
        state = _RECOVERY_STATES.pop(action["recovery_state"], None)
        if state is None:
            raise ValueError("emergency rollback recovery state differs")
        try:
            os.replace(state["config"], config_path)
            os.replace(state["metadata"], metadata_path)
            if state["temporary"] is None:
                temporary_path.unlink(missing_ok=True)
            else:
                os.replace(state["temporary"], temporary_path)
        finally:
            for backup in state.values():
                if backup is not None:
                    backup.unlink(missing_ok=True)
        return {"recovered": True, "recovery_syncconf_path": str(config_path)}
    if action["action"] != "remove":
        raise ValueError("emergency rollback filesystem action differs")
    expected_pre = rollback_expected_observation(action, phase="pre")
    _require_rollback_observation(
        _system_rollback_observation(action), expected_pre, "apply-time pre"
    )
    config_text = _read_atomic_file(config_path, 1048576).decode(
        "utf-8", errors="strict"
    )
    metadata = json.loads(
        _read_atomic_file(metadata_path, 1048576).decode("utf-8", errors="strict")
    )
    prefix, blocks = _config_peer_blocks(config_text)
    rows, shape = _metadata_rows(metadata)
    matching_blocks = [
        block for block in blocks if _block_fingerprint(block) == candidate
    ]
    matching_rows = [row for row in rows if _row_fingerprint(row) == candidate]
    if len(matching_blocks) != 1 or len(matching_rows) != 1:
        raise ValueError("candidate identity differs before removal")
    kept_blocks = [block for block in blocks if _block_fingerprint(block) != candidate]
    config_bytes = "".join(
        prefix + [line for block in kept_blocks for line in block]
    ).encode()
    kept_rows = [row for row in rows if _row_fingerprint(row) != candidate]
    metadata_value: Any = kept_rows if shape == "list" else {"peers": kept_rows}
    token = os.urandom(32).hex()
    recovery_root = temporary_path.parent
    config_backup = recovery_root / (".recovery-" + token + ".conf")
    metadata_backup = recovery_root / (".recovery-" + token + ".json")
    temporary_backup = recovery_root / (".recovery-" + token + ".tmp")
    _backup_exact_file(config_path, config_backup)
    try:
        _backup_exact_file(metadata_path, metadata_backup)
        if temporary_path.exists():
            _backup_exact_file(temporary_path, temporary_backup)
            saved_temporary: pathlib.Path | None = temporary_backup
        else:
            saved_temporary = None
        state = {
            "config": config_backup,
            "metadata": metadata_backup,
            "temporary": saved_temporary,
        }
        _atomic_replace(config_path, config_bytes)
        _atomic_replace(metadata_path, _canonical(metadata_value))
        temporary_path.unlink(missing_ok=True)
        _RECOVERY_STATES[token] = state
        return {"removed": True, "recovery_state": token}
    except Exception:
        if config_backup.exists():
            os.replace(config_backup, config_path)
        if metadata_backup.exists():
            os.replace(metadata_backup, metadata_path)
        if temporary_backup.exists():
            os.replace(temporary_backup, temporary_path)
        raise


def _system_syncconf(path: pathlib.Path) -> None:
    if not path.is_absolute() or pathlib.PurePosixPath(
        str(path)
    ).parent != pathlib.PurePosixPath("/run/home-gateway-p3-peer-guard"):
        raise ValueError("syncconf path differs")
    run_checked_command(["/usr/bin/awg", "syncconf", "awg0", str(path)])


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument(
        "mode",
        nargs="?",
        choices=(
            "attest",
            "reconcile",
            "guard",
            "client-observe",
            "emergency-rollback",
        ),
    )
    parser.add_argument("operation", nargs="?", choices=("admin", "guest"))
    args = parser.parse_args()
    if args.self_test:
        if args.mode is not None or args.operation is not None:
            parser.error("--self-test cannot be combined with a mode")
        _self_test()
        return 0
    if args.mode is None:
        parser.error("one explicit mode is required")
    request = read_exact_request(sys.stdin.buffer)
    if args.mode == "attest":
        receipt = _attest(request)
        print(json.dumps(receipt, separators=(",", ":")))
        return 0
    if args.mode == "reconcile":
        receipt = run_reconcile(request, _system_collector)
        print(json.dumps(receipt, separators=(",", ":")))
        return 0
    if args.mode == "guard":
        if args.operation is None:
            parser.error("guard requires admin or guest")
        terminal = "stopped"
        for event in run_guard(
            args.operation, request, _system_collector, time.monotonic
        ):
            print(json.dumps(event, separators=(",", ":")), flush=True)
            terminal = event["event"]
        return 0 if terminal == "candidate" else 1
    if args.mode == "client-observe":
        receipt = run_client_observe(request, _system_client_collector, time.monotonic)
        print(json.dumps(receipt, separators=(",", ":")))
        return 0
    receipt = run_emergency_rollback(
        request, _system_atomic_filesystem, _system_syncconf
    )
    print(json.dumps(receipt, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, RuntimeError):
        print('{"error":"P3_GUARD_FAILED"}', file=sys.stderr)
        raise SystemExit(1) from None
