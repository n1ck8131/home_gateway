#!/usr/bin/env python3
"""Bounded, attested P3 server peer guard and read-only observer."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import pathlib
import re
import shlex
import stat
import subprocess
import sys
import threading
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
    "/usr/sbin/nft",
    "/usr/bin/systemctl",
    "/usr/bin/sha256sum",
}
MAX_NFT_COMPAT_WARNING_BYTES = 4096
NFT_IPTABLES_COMPAT_WARNING_RE = re.compile(
    rb"(?:# Warning: table (?:ip|ip6) [A-Za-z0-9_.-]{1,64} "
    rb"is managed by iptables-nft, do not touch!\n)+"
)
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
    "nonce",
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
    "baseline_ipv6_policy_sha256",
}
ROLLBACK_KEYS = (
    COMMON_REQUEST_KEYS
    | ROLLBACK_PLAN_KEYS
    | {
        "rollback_plan_sha256",
        "confirmation",
    }
)
SERVER_BASELINE_KEYS = (
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
    "persistent_config_sha256",
    "persistent_peer_set_sha256",
    "live_peer_set_sha256",
    "metadata_peer_set_sha256",
    "metadata_sha256",
    "candidate_leftover_count",
    "temporary_leftover_count",
    "atomic_leftover_count",
    "firewall_identity_sha256",
    "runtime_identity_sha256",
    "temporary_state_sha256",
    "payload_sha256",
    "protocol_sha256",
)
SERVER_IDENTITY_KEYS = SERVER_BASELINE_KEYS


@dataclass(frozen=True)
class CommandResult:
    exit_code: int
    stdout: bytes
    stderr: bytes
    overflowed: bool = False
    timed_out: bool = False


CommandRunner: TypeAlias = Callable[[Sequence[str], int, int], CommandResult]
StreamCommandRunner: TypeAlias = Callable[
    [Sequence[str], bytes, int, int], CommandResult
]
FileReader: TypeAlias = Callable[[pathlib.Path, int], bytes]
FileLister: TypeAlias = Callable[[pathlib.Path], Sequence[pathlib.Path]]
Collector: TypeAlias = Callable[[dict[str, Any]], dict[str, Any]]
Clock: TypeAlias = Callable[[], float]
AtomicFilesystem: TypeAlias = Callable[[dict[str, Any]], dict[str, Any]]
SyncconfRunner: TypeAlias = Callable[[pathlib.Path, str], None]


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
            "baseline_ipv6_policy_sha256",
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
        exact_paths = {
            "persistent_config_path": CONTAINER_CONFIG_PATH,
            "metadata_path": CONTAINER_CLIENTS_PATH,
            "temporary_path": f"/tmp/p3-candidate-{nonce[:32]}.tmp",
            "syncconf_path": CONTAINER_CONFIG_PATH,
        }
        for name, expected_path in exact_paths.items():
            if request[name] != expected_path:
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


def _run_bounded_process(
    arguments: Sequence[str],
    data: bytes | None,
    timeout_seconds: int,
    maximum_bytes: int,
) -> CommandResult:
    """Run one child without ever retaining unbounded stdout or stderr."""
    process = subprocess.Popen(
        list(arguments),
        stdin=subprocess.PIPE if data is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    overflow = threading.Event()
    stdout = bytearray()
    stderr = bytearray()

    def bounded_reader(stream: BinaryIO, retained: bytearray) -> None:
        while True:
            chunk = stream.read(4096)
            if not chunk:
                return
            remaining = maximum_bytes + 1 - len(retained)
            if remaining > 0:
                retained.extend(chunk[:remaining])
            if len(chunk) > remaining or len(retained) > maximum_bytes:
                overflow.set()
                try:
                    process.kill()
                except OSError:
                    pass
                return

    readers = [
        threading.Thread(target=bounded_reader, args=(process.stdout, stdout)),
        threading.Thread(target=bounded_reader, args=(process.stderr, stderr)),
    ]
    for reader in readers:
        reader.start()

    writer: threading.Thread | None = None
    if data is not None:

        def bounded_writer() -> None:
            try:
                assert process.stdin is not None
                process.stdin.write(data)
                process.stdin.close()
            except (BrokenPipeError, OSError):
                pass

        writer = threading.Thread(target=bounded_writer)
        writer.start()

    timed_out = False
    try:
        process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        process.kill()
        process.wait()
    finally:
        if writer is not None:
            writer.join()
        for reader in readers:
            reader.join()
        assert process.stdout is not None and process.stderr is not None
        process.stdout.close()
        process.stderr.close()
    return CommandResult(
        process.returncode,
        bytes(stdout),
        bytes(stderr),
        overflow.is_set(),
        timed_out,
    )


def _default_command_runner(
    arguments: Sequence[str], timeout_seconds: int, maximum_bytes: int
) -> CommandResult:
    return _run_bounded_process(arguments, None, timeout_seconds, maximum_bytes)


def _default_stream_command_runner(
    arguments: Sequence[str], data: bytes, timeout_seconds: int, maximum_bytes: int
) -> CommandResult:
    return _run_bounded_process(arguments, data, timeout_seconds, maximum_bytes)


def run_checked_stream_command(
    arguments: Sequence[str],
    data: bytes,
    *,
    runner: StreamCommandRunner = _default_stream_command_runner,
    timeout_seconds: int = 10,
    maximum_bytes: int = MAX_COMMAND_BYTES,
) -> bytes:
    if not arguments or arguments[0] != "/usr/bin/docker":
        raise ValueError("stream command executable is not allowlisted")
    if not isinstance(data, bytes) or not data or len(data) > MAX_COMMAND_BYTES:
        raise ValueError("stream command input differs")
    result = runner(tuple(arguments), data, timeout_seconds, maximum_bytes)
    if (
        result.timed_out
        or result.overflowed
        or result.exit_code != 0
        or result.stderr
        or len(result.stdout) > maximum_bytes
    ):
        raise ValueError("allowlisted stream command failed")
    return result.stdout


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
    if result.timed_out:
        raise ValueError("allowlisted command timeout")
    if result.overflowed:
        raise ValueError("allowlisted command output exceeds bound")
    if result.exit_code != 0:
        raise ValueError("allowlisted command exit differs")
    if result.stderr:
        raise ValueError("allowlisted command emitted stderr")
    if len(result.stdout) > maximum_bytes:
        raise ValueError("allowlisted command output exceeds bound")
    return result.stdout


def run_nft_ruleset_command(
    *,
    runner: CommandRunner = _default_command_runner,
    timeout_seconds: int = 10,
    maximum_bytes: int = MAX_COMMAND_BYTES,
) -> bytes:
    def nft_runner(
        arguments: Sequence[str], timeout: int, maximum: int
    ) -> CommandResult:
        result = runner(arguments, timeout, maximum)
        if (
            result.stderr
            and len(result.stderr) <= MAX_NFT_COMPAT_WARNING_BYTES
            and NFT_IPTABLES_COMPAT_WARNING_RE.fullmatch(result.stderr) is not None
        ):
            return CommandResult(
                result.exit_code,
                result.stdout,
                b"",
                result.overflowed,
                result.timed_out,
            )
        return result

    return run_checked_command(
        ["/usr/sbin/nft", "list", "ruleset"],
        runner=nft_runner,
        timeout_seconds=timeout_seconds,
        maximum_bytes=maximum_bytes,
    )


def _read_utf8_lines(data: bytes, label: str) -> list[str]:
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{label} UTF-8 differs") from exc
    return [line for line in text.splitlines() if line]


def _public_key_fingerprint(value: str) -> str:
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("peer public key differs") from exc
    if len(decoded) != 32 or base64.b64encode(decoded).decode("ascii") != value:
        raise ValueError("peer public key differs")
    return _sha(decoded)


def _normalize_policy(data: bytes) -> bytes:
    try:
        text = data.decode("utf-8", errors="strict").replace("\r\n", "\n")
    except UnicodeDecodeError as exc:
        raise ValueError("host policy UTF-8 differs") from exc
    if "\r" in text:
        raise ValueError("host policy line ending differs")
    result = []
    generated = re.compile(r"^# (?:Generated|Completed) by .+ on .+$")
    completed = re.compile(
        r"# Completed on (?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) "
        r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) "
        r"(?: [1-9]|[12][0-9]|3[01]) (?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9] [0-9]{4}"
    )
    for line in text.splitlines():
        if generated.fullmatch(line) or completed.fullmatch(line):
            continue
        if re.match(r"# Completed on (?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\b", line):
            raise ValueError("host policy completion timestamp differs")
        chain = re.fullmatch(r"(:[^ ]+ (?:ACCEPT|DROP|REJECT|-) )\[\d+:\d+\]", line)
        if chain is not None:
            line = chain.group(1) + "[0:0]"
        if re.match(r"^\[\d+:\d+\]", line):
            raise ValueError("host policy counters differ")
        result.append(line)
    return ("\n".join(result) + "\n").encode("utf-8")


def _normalize_ipv6_policy(data: bytes) -> bytes:
    try:
        text = data.decode("utf-8", errors="strict").replace("\r\n", "\n")
    except UnicodeDecodeError as exc:
        raise ValueError("host policy UTF-8 differs") from exc
    if "\r" in text:
        raise ValueError("host policy line ending differs")
    result = []
    for line in text.splitlines():
        if line.startswith("#"):
            continue
        chain = re.fullmatch(r"(:[^ ]+ (?:ACCEPT|DROP|REJECT|-) )\[\d+:\d+\]", line)
        if chain is not None:
            line = chain.group(1) + "[0:0]"
        rule = re.fullmatch(r"\[\d+:\d+\] (-A .+)", line)
        if rule is not None:
            line = rule.group(1)
        elif re.match(r"^\[\d+:\d+\]", line):
            raise ValueError("host policy counters differ")
        result.append(line)
    return ("\n".join(result) + "\n").encode("utf-8")


def normalized_policy_sha256(data: bytes) -> str:
    return _sha(_normalize_ipv6_policy(data))


def _parse_ipv6_policy_sample(data: bytes) -> dict[str, Any]:
    parse_complete = True
    parse_failures: set[str] = set()
    policy_comment_line_count = 0
    tables: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    seen_table_names: set[str] = set()

    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return {
            "docker_user_chain_class": "ambiguous",
            "docker_user_declaration_count": 0,
            "docker_user_rule_count": 0,
            "forward_jump_count": 0,
            "forward_jump_position_class": "absent",
            "project_owned_chain_count": 0,
            "project_owned_jump_count": 0,
            "project_owned_comment_count": 0,
            "policy_comment_line_count": 0,
            "parse_complete": False,
            "parse_failure_classes": ["invalid_utf8"],
        }

    for line in text.splitlines():
        if not line:
            parse_complete = False
            parse_failures.add("blank_line")
            continue
        if line.startswith("#"):
            policy_comment_line_count += 1
            if re.fullmatch(
                r"# (?:Warning: (?:ip6tables-(?:legacy|nft) tables present, use "
                r"ip6tables-(?:legacy|nft)-save to see them)|Table .+ is incompatible, "
                r"use .+ tool\.)",
                line,
            ):
                parse_complete = False
                parse_failures.add("incomplete_backend_view")
            continue
        counted_rule = re.fullmatch(r"\[\d+:\d+\] (-A .+)", line)
        if counted_rule is not None:
            line = counted_rule.group(1)
        if current is None:
            if not re.fullmatch(r"\*[A-Za-z0-9_-]+", line):
                parse_complete = False
                parse_failures.add("unexpected_top_level_line")
                continue
            table_name = line[1:]
            if table_name in seen_table_names:
                parse_complete = False
                parse_failures.add("duplicate_table")
            seen_table_names.add(table_name)
            current = {
                "name": table_name,
                "chains": [],
                "chain_set": set(),
                "rules": [],
                "rule_set": set(),
                "rules_started": False,
            }
            continue
        if line == "COMMIT":
            tables.append(current)
            current = None
            continue
        chain_match = re.fullmatch(
            r":([A-Za-z0-9_.:+-]+) (?:ACCEPT|DROP|REJECT|-) \[\d+:\d+\]",
            line,
        )
        if chain_match is not None:
            chain = chain_match.group(1)
            if current["rules_started"] or chain in current["chain_set"]:
                parse_complete = False
                parse_failures.add(
                    "chain_after_rule"
                    if current["rules_started"]
                    else "duplicate_chain"
                )
            current["chains"].append(chain)
            current["chain_set"].add(chain)
            continue
        if not line.startswith("-A "):
            parse_complete = False
            parse_failures.add("unexpected_table_line")
            continue
        current["rules_started"] = True
        try:
            tokens = shlex.split(line, comments=False, posix=True)
        except ValueError:
            parse_complete = False
            parse_failures.add("invalid_rule_quoting")
            continue
        if len(tokens) < 3 or tokens[0] != "-A":
            parse_complete = False
            parse_failures.add("invalid_rule_shape")
            continue
        rule = tuple(tokens)
        current["rule_set"].add(rule)
        current["rules"].append(rule)

    if current is not None:
        parse_complete = False
        parse_failures.add("unclosed_table")
        tables.append(current)

    filter_tables = [table for table in tables if table["name"] == "filter"]
    if len(filter_tables) != 1:
        parse_complete = False
        parse_failures.add("filter_table_count")
    filter_table = filter_tables[0] if len(filter_tables) == 1 else None
    if filter_table is None:
        return {
            "docker_user_chain_class": "ambiguous",
            "docker_user_declaration_count": 0,
            "docker_user_rule_count": 0,
            "forward_jump_count": 0,
            "forward_jump_position_class": "absent",
            "project_owned_chain_count": 0,
            "project_owned_jump_count": 0,
            "project_owned_comment_count": 0,
            "policy_comment_line_count": policy_comment_line_count,
            "parse_complete": False,
            "parse_failure_classes": sorted(parse_failures),
        }

    chains = filter_table["chains"]
    docker_declarations = sum(chain == "DOCKER-USER" for chain in chains)
    owned_chain_count = sum(
        chain == "HG-P3-IN" for table in tables for chain in table["chains"]
    )
    docker_rules: list[tuple[str, ...]] = []
    forward_rules: list[tuple[str, ...]] = []
    forward_jump_count = 0
    owned_jump_count = 0
    owned_comment_count = 0

    for table, rule in ((item, entry) for item in tables for entry in item["rules"]):
        source_chain = rule[1]
        if source_chain not in table["chain_set"]:
            parse_complete = False
            parse_failures.add("undeclared_source_chain")
        if table is filter_table and source_chain == "DOCKER-USER":
            docker_rules.append(rule)
        if table is filter_table and source_chain == "FORWARD":
            forward_rules.append(rule)

        targets = []
        comments = []
        index = 2
        while index < len(rule):
            token = rule[index]
            if token in {"-j", "--jump", "-g", "--goto"}:
                if index + 1 >= len(rule):
                    parse_complete = False
                    parse_failures.add("missing_target_argument")
                    break
                targets.append(rule[index + 1])
                index += 2
                continue
            if token == "--comment":
                if index + 1 >= len(rule):
                    parse_complete = False
                    parse_failures.add("missing_comment_argument")
                    break
                comments.append(rule[index + 1])
                index += 2
                continue
            index += 1
        if len(targets) > 1 or len(comments) > 1:
            parse_complete = False
            if len(targets) > 1:
                parse_failures.add("multiple_targets")
            if len(comments) > 1:
                parse_failures.add("multiple_comments")
        if targets:
            target = targets[0]
            if (
                table is filter_table
                and source_chain == "FORWARD"
                and target == "DOCKER-USER"
            ):
                forward_jump_count += 1
            if target == "HG-P3-IN":
                owned_jump_count += 1
        owned_comment_count += sum(
            comment == "home-gateway-gate64b" for comment in comments
        )

    if docker_declarations > 1:
        docker_class = "ambiguous"
    elif docker_declarations == 0:
        docker_class = "missing"
    elif not docker_rules:
        docker_class = "empty"
    elif len(docker_rules) == 1 and docker_rules[0] in {
        ("-A", "DOCKER-USER", "-j", "RETURN"),
        ("-A", "DOCKER-USER", "--jump", "RETURN"),
    }:
        docker_class = "return_only"
    else:
        docker_class = "nonempty"

    if forward_jump_count == 0:
        forward_position = "absent"
    else:
        unconditional = bool(forward_rules) and forward_rules[0] in {
            ("-A", "FORWARD", "-j", "DOCKER-USER"),
            ("-A", "FORWARD", "--jump", "DOCKER-USER"),
        }
        forward_position = "first" if unconditional else "not_first"

    return {
        "docker_user_chain_class": docker_class,
        "docker_user_declaration_count": docker_declarations,
        "docker_user_rule_count": len(docker_rules),
        "forward_jump_count": forward_jump_count,
        "forward_jump_position_class": forward_position,
        "project_owned_chain_count": owned_chain_count,
        "project_owned_jump_count": owned_jump_count,
        "project_owned_comment_count": owned_comment_count,
        "policy_comment_line_count": policy_comment_line_count,
        "parse_complete": parse_complete,
        "parse_failure_classes": sorted(parse_failures),
    }


def classify_ipv6_policy_samples(
    samples: Sequence[bytes], expected_ipv6_policy_sha256: str
) -> dict[str, Any]:
    if len(samples) != 3:
        raise ValueError("exactly three IPv6 policy samples are required")
    if any(not isinstance(sample, bytes) for sample in samples):
        raise TypeError("IPv6 policy samples must be bytes")
    if not _is_sha256(expected_ipv6_policy_sha256):
        raise ValueError("expected IPv6 policy identity differs")

    normalized_samples = []
    sample_hashes = []
    parsed_samples = []
    for sample in samples:
        try:
            normalized = _normalize_ipv6_policy(sample)
        except ValueError:
            normalized = sample
            parsed = _parse_ipv6_policy_sample(b"")
        else:
            parsed = _parse_ipv6_policy_sample(sample)
        normalized_samples.append(normalized)
        sample_hashes.append(_sha(normalized))
        parsed_samples.append(parsed)

    unique_count = len(set(sample_hashes))
    observed_sha256 = sample_hashes[0] if unique_count == 1 else None
    if observed_sha256 is None:
        relation = "unstable"
    elif observed_sha256 == expected_ipv6_policy_sha256:
        relation = "historical_match"
    else:
        relation = "stable_mismatch"

    docker_classes = {parsed["docker_user_chain_class"] for parsed in parsed_samples}
    docker_class = (
        next(iter(docker_classes)) if len(docker_classes) == 1 else "ambiguous"
    )
    forward_positions = {
        parsed["forward_jump_position_class"] for parsed in parsed_samples
    }
    forward_position = (
        next(iter(forward_positions)) if len(forward_positions) == 1 else "not_first"
    )
    parse_complete = all(parsed["parse_complete"] for parsed in parsed_samples)
    docker_rule_count = max(
        parsed["docker_user_rule_count"] for parsed in parsed_samples
    )
    docker_declaration_count = max(
        parsed["docker_user_declaration_count"] for parsed in parsed_samples
    )
    forward_jump_count = max(parsed["forward_jump_count"] for parsed in parsed_samples)
    owned_chain_count = max(
        parsed["project_owned_chain_count"] for parsed in parsed_samples
    )
    owned_jump_count = max(
        parsed["project_owned_jump_count"] for parsed in parsed_samples
    )
    owned_comment_count = max(
        parsed["project_owned_comment_count"] for parsed in parsed_samples
    )
    policy_comment_line_count = max(
        parsed["policy_comment_line_count"] for parsed in parsed_samples
    )
    parse_failure_classes = sorted(
        {
            failure
            for parsed in parsed_samples
            for failure in parsed["parse_failure_classes"]
        }
    )
    project_scope_nonmutation_confirmed = parse_complete and not any(
        (owned_chain_count, owned_jump_count, owned_comment_count)
    )
    rebaseline_eligible = (
        unique_count == 1
        and parse_complete
        and docker_class in {"empty", "return_only"}
        and forward_jump_count == 1
        and forward_position == "first"
        and project_scope_nonmutation_confirmed
    )
    return {
        "expected_ipv6_policy_sha256": expected_ipv6_policy_sha256,
        "observed_ipv6_policy_sha256": observed_sha256,
        "sample_set_sha256": _sha(sorted(sample_hashes)),
        "sample_count": len(normalized_samples),
        "unique_policy_identity_count": unique_count,
        "whole_policy_relation_class": relation,
        "docker_user_chain_class": docker_class,
        "docker_user_declaration_count": docker_declaration_count,
        "docker_user_rule_count": docker_rule_count,
        "forward_jump_count": forward_jump_count,
        "forward_jump_position_class": forward_position,
        "project_owned_chain_count": owned_chain_count,
        "project_owned_jump_count": owned_jump_count,
        "project_owned_comment_count": owned_comment_count,
        "policy_comment_line_count": policy_comment_line_count,
        "parse_complete": parse_complete,
        "parse_failure_classes": parse_failure_classes,
        "project_scope_nonmutation_confirmed": project_scope_nonmutation_confirmed,
        "rebaseline_eligible": rebaseline_eligible,
    }


def _normalize_nft(data: bytes) -> bytes:
    try:
        text = data.decode("utf-8", errors="strict").replace("\r\n", "\n")
    except UnicodeDecodeError as exc:
        raise ValueError("nft policy UTF-8 differs") from exc
    if "\r" in text:
        raise ValueError("nft policy line ending differs")
    normalized = re.sub(
        r"\bcounter packets \d+ bytes \d+\b", "counter packets 0 bytes 0", text
    )
    if (
        re.search(r"\bcounter\b", normalized)
        and "counter packets 0 bytes 0" not in normalized
    ):
        raise ValueError("nft counter shape differs")
    return (normalized.rstrip("\n") + "\n").encode("utf-8")


def _listener_identity(data: bytes) -> tuple[int, str]:
    rows = []
    for line in _read_utf8_lines(data, "listener"):
        fields = line.split()
        if len(fields) != 6 or not fields[2].isdigit() or not fields[3].isdigit():
            raise ValueError("listener observation differs")
        rows.append([fields[0], fields[1], 0, 0, fields[4], fields[5]])
    if len(rows) != len({tuple(row) for row in rows}):
        raise ValueError("listener observation is ambiguous")
    rows.sort()
    return len(rows), _sha(rows)


def _udp_publication_identity(data: bytes) -> str:
    classes = []
    for line in _read_utf8_lines(data, "UDP publication"):
        if line == "0.0.0.0:38556":
            classes.append("all_ipv4")
        elif line == "[::]:38556":
            classes.append("all_ipv6")
        else:
            raise ValueError("UDP publication differs")
    if sorted(classes) != ["all_ipv4", "all_ipv6"]:
        raise ValueError("UDP publication count differs")
    return _sha(sorted(classes))


def collect_server_snapshot(
    request: dict[str, Any],
    runner: CommandRunner = _default_command_runner,
) -> dict[str, Any]:
    rows = _read_utf8_lines(
        run_checked_command(
            [
                "/usr/bin/docker",
                "ps",
                "--no-trunc",
                "-a",
                "--filter",
                "name=^/amnezia-awg2$",
                "--format",
                (
                    '{"ID":{{json .ID}},"Image":{{json .Image}},'
                    '"Names":{{json .Names}},"State":{{json .State}}}'
                ),
            ],
            runner=runner,
        ),
        "container observation",
    )
    if len(rows) != 1:
        raise ValueError("container count differs")
    try:
        row = json.loads(rows[0])
    except json.JSONDecodeError as exc:
        raise ValueError("container observation differs") from exc
    if (
        not isinstance(row, dict)
        or set(row) != {"ID", "Image", "Names", "State"}
        or row.get("Names") != "amnezia-awg2"
        or row.get("State") != "running"
        or not isinstance(row.get("ID"), str)
    ):
        raise ValueError("container observation differs")
    container_id = row["ID"]
    try:
        inspect_values = json.loads(
            run_checked_command(
                ["/usr/bin/docker", "inspect", container_id], runner=runner
            ).decode("utf-8", errors="strict")
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("container inspect observation differs") from exc
    if not isinstance(inspect_values, list) or len(inspect_values) != 1:
        raise ValueError("container inspect observation differs")
    inspect = inspect_values[0]
    try:
        image_id = inspect["Image"]
        restart_count = inspect["RestartCount"]
        running = inspect["State"]["Running"]
        restarting = inspect["State"]["Restarting"]
        restart_policy = inspect["HostConfig"]["RestartPolicy"]["Name"]
    except (KeyError, TypeError) as exc:
        raise ValueError("container inspect observation differs") from exc
    if (
        inspect.get("Id") != container_id
        or inspect.get("Name") != "/amnezia-awg2"
        or not isinstance(restart_count, int)
        or isinstance(restart_count, bool)
        or running is not True
        or restarting is not False
        or restart_policy not in {"unless-stopped", "always"}
        or not isinstance(image_id, str)
    ):
        raise ValueError("container inspect observation differs")
    try:
        image_values = json.loads(
            run_checked_command(
                ["/usr/bin/docker", "image", "inspect", image_id], runner=runner
            ).decode("utf-8", errors="strict")
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("image inspect observation differs") from exc
    if not isinstance(image_values, list) or len(image_values) != 1:
        raise ValueError("image inspect observation differs")
    image = image_values[0]
    digests = image.get("RepoDigests")
    if (
        image.get("Id") != image_id
        or not isinstance(digests, list)
        or not digests
        or any(not isinstance(value, str) or not value for value in digests)
        or len(set(digests)) != len(digests)
    ):
        raise ValueError("image inspect observation differs")
    ports = run_checked_command(
        ["/usr/bin/docker", "port", container_id, "38556/udp"], runner=runner
    )
    publication_hash = _udp_publication_identity(ports)
    config_bytes = run_checked_command(
        ["/usr/bin/docker", "exec", container_id, "cat", "/opt/amnezia/awg/awg0.conf"],
        runner=runner,
        maximum_bytes=MAX_COMMAND_BYTES,
    )
    clients_bytes = run_checked_command(
        [
            "/usr/bin/docker",
            "exec",
            container_id,
            "cat",
            "/opt/amnezia/awg/clientsTable",
        ],
        runner=runner,
        maximum_bytes=MAX_COMMAND_BYTES,
    )
    live_bytes = run_checked_command(
        [
            "/usr/bin/docker",
            "exec",
            container_id,
            "/usr/bin/awg",
            "show",
            "awg0",
            "peers",
        ],
        runner=runner,
    )
    temp_bytes = run_checked_command(
        [
            "/usr/bin/docker",
            "exec",
            container_id,
            "/bin/bash",
            "-c",
            'shopt -s nullglob; for f in /tmp/*.tmp; do [ -f "$f" ] && printf \'%s\\0\' "${f##*/}"; done',
        ],
        runner=runner,
    )
    try:
        config_text = config_bytes.decode("utf-8", errors="strict")
        clients_value = json.loads(clients_bytes.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("container state encoding differs") from exc
    _, blocks = _config_peer_blocks(config_text)
    persistent_peers = []
    for block in blocks:
        fingerprint = _block_fingerprint(block)
        if fingerprint is None:
            raise ValueError("persistent peer schema differs")
        persistent_peers.append(fingerprint)
    persistent_peers.sort()
    if len(set(persistent_peers)) != len(persistent_peers):
        raise ValueError("persistent peer identity is ambiguous")
    rows, _ = _metadata_rows(clients_value)
    metadata_peers = sorted(_row_fingerprint(item) for item in rows)
    live_peers = sorted(
        _public_key_fingerprint(line)
        for line in _read_utf8_lines(live_bytes, "peer observation")
    )
    if persistent_peers != live_peers or persistent_peers != metadata_peers:
        raise ValueError("peer set convergence differs")
    try:
        temp_names = [
            value.decode("utf-8", errors="strict")
            for value in temp_bytes.split(b"\0")
            if value
        ]
    except UnicodeDecodeError as exc:
        raise ValueError("temporary name encoding differs") from exc
    if len(temp_names) != len(set(temp_names)) or any(
        not re.fullmatch(r"[A-Za-z0-9._-]+\.tmp", name) for name in temp_names
    ):
        raise ValueError("temporary name shape differs")
    listener_bytes = run_checked_command(["/usr/bin/ss", "-H", "-lntu"], runner=runner)
    listener_count, listener_hash = _listener_identity(listener_bytes)
    ipv4_policy = _normalize_policy(
        run_checked_command(["/usr/sbin/iptables-save"], runner=runner)
    )
    ipv6_samples = [
        run_checked_command(["/usr/sbin/ip6tables-save"], runner=runner)
        for _ in range(3)
    ]
    ipv6_diagnostic = classify_ipv6_policy_samples(
        ipv6_samples, request["expected_ipv6_policy_sha256"]
    )
    if not ipv6_diagnostic["rebaseline_eligible"]:
        raise ValueError("IPv6 structural non-mutation differs")
    nft_policy = _normalize_nft(run_nft_ruleset_command(runner=runner))
    policy_state = (
        run_checked_command(
            ["/usr/bin/systemctl", "is-active", "home-gateway-docker-policy.service"],
            runner=runner,
        )
        .decode("utf-8", errors="strict")
        .strip()
    )
    host_policy_hash = _sha(ipv4_policy)
    ipv6_policy_hash = ipv6_diagnostic["observed_ipv6_policy_sha256"]
    firewall_hash = _sha(
        {
            "host_policy_sha256": host_policy_hash,
            "ipv6_policy_sha256": ipv6_policy_hash,
            "nft_policy_sha256": _sha(nft_policy),
        }
    )
    snapshot = {
        "container_count": 1,
        "container_running": True,
        "container_identity_sha256": _sha(container_id.encode("utf-8")),
        "image_identity_sha256": _sha(
            {"image_id": image_id, "repo_digests": sorted(digests)}
        ),
        "container_restart_count": restart_count,
        "udp_publication_count": 1,
        "udp_publication_sha256": publication_hash,
        "public_listener_class_count": listener_count,
        "listener_identity_sha256": listener_hash,
        "host_policy_loaded": policy_state == "active",
        "host_policy_sha256": host_policy_hash,
        "ipv6_non_mutation": (
            ipv6_diagnostic["project_scope_nonmutation_confirmed"]
            and ipv6_policy_hash == request["expected_ipv6_policy_sha256"]
        ),
        "ipv6_policy_sha256": ipv6_policy_hash,
        "peer_fingerprint_sha256": live_peers,
        "persistent_config_sha256": _sha(config_bytes),
        "persistent_peer_set_sha256": _sha(persistent_peers),
        "live_peer_set_sha256": _sha(live_peers),
        "metadata_peer_set_sha256": _sha(metadata_peers),
        "metadata_sha256": _sha(clients_bytes),
        "candidate_leftover_count": sum("candidate" in name for name in temp_names),
        "temporary_leftover_count": len(temp_names),
        "atomic_leftover_count": sum(".p3-next-" in name for name in temp_names),
        "firewall_identity_sha256": firewall_hash,
        "temporary_state_sha256": _sha(sorted(temp_names)),
        "payload_sha256": own_payload_sha256(),
        "protocol_sha256": public_protocol_sha256(),
    }
    snapshot["runtime_identity_sha256"] = _sha(
        {
            name: snapshot[name]
            for name in (
                "container_count",
                "container_running",
                "container_identity_sha256",
                "image_identity_sha256",
                "container_restart_count",
                "udp_publication_count",
                "udp_publication_sha256",
                "public_listener_class_count",
                "listener_identity_sha256",
                "firewall_identity_sha256",
                "host_policy_loaded",
                "host_policy_sha256",
                "ipv6_non_mutation",
                "ipv6_policy_sha256",
            )
        }
    )
    return snapshot


def server_baseline_sha256(snapshot: dict[str, Any]) -> str:
    if not isinstance(snapshot, dict) or set(snapshot) != set(SERVER_BASELINE_KEYS):
        raise ValueError("server snapshot schema differs")
    for name in (
        "container_count",
        "container_restart_count",
        "udp_publication_count",
        "public_listener_class_count",
        "candidate_leftover_count",
        "temporary_leftover_count",
        "atomic_leftover_count",
    ):
        if isinstance(snapshot[name], bool) or not isinstance(snapshot[name], int):
            raise TypeError(f"server {name} type differs")
    for name in ("container_running", "host_policy_loaded", "ipv6_non_mutation"):
        if not isinstance(snapshot[name], bool):
            raise TypeError(f"server {name} type differs")
    for name in (
        "container_identity_sha256",
        "firewall_identity_sha256",
        "host_policy_sha256",
        "image_identity_sha256",
        "ipv6_policy_sha256",
        "listener_identity_sha256",
        "live_peer_set_sha256",
        "metadata_peer_set_sha256",
        "metadata_sha256",
        "payload_sha256",
        "persistent_config_sha256",
        "persistent_peer_set_sha256",
        "protocol_sha256",
        "runtime_identity_sha256",
        "temporary_state_sha256",
        "udp_publication_sha256",
    ):
        if not _is_sha256(snapshot[name]):
            raise ValueError(f"server {name} differs")
    peers = snapshot["peer_fingerprint_sha256"]
    if (
        not isinstance(peers, list)
        or len(peers) > 1024
        or len(set(peers)) != len(peers)
        or any(not _is_sha256(peer) for peer in peers)
    ):
        raise ValueError("server peer set schema differs")
    canonical = dict(snapshot)
    canonical["peer_fingerprint_sha256"] = sorted(peers)
    return _sha(canonical)


def _server_identity(snapshot: dict[str, Any]) -> str:
    return server_baseline_sha256(snapshot)


def _require_snapshot_hash(snapshot: dict[str, Any], name: str) -> str:
    value = snapshot.get(name)
    if not _is_sha256(value):
        raise ValueError(f"server {name} differs")
    return value


def _validate_baseline_snapshot(
    request: dict[str, Any], snapshot: dict[str, Any]
) -> dict[str, Any]:
    server_baseline_sha256(snapshot)
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
    return "candidate", candidate


def _guard_snapshot_identity(snapshot: dict[str, Any]) -> str:
    selected = {name: snapshot.get(name) for name in SERVER_IDENTITY_KEYS}
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

CONTAINER_CONFIG_PATH = "/opt/amnezia/awg/awg0.conf"
CONTAINER_CLIENTS_PATH = "/opt/amnezia/awg/clientsTable"
CONTAINER_INTERFACE = "awg0"


def container_staging_paths(nonce: str) -> tuple[str, str]:
    if not _is_sha256(nonce):
        raise ValueError("rollback nonce differs")
    token = nonce[:32]
    root = "/opt/amnezia/awg/.p3-next-" + token
    return root + ".conf", root + ".clients"


def temporary_recovery_staging_path(nonce: str) -> str:
    if not _is_sha256(nonce):
        raise ValueError("rollback nonce differs")
    return "/tmp/.p3-recover-" + nonce[:32] + ".tmp"


def container_writer_arguments(
    container_id: str, target: str, staging: str, byte_count: int
) -> list[str]:
    if (
        not isinstance(container_id, str)
        or not container_id
        or target not in {CONTAINER_CONFIG_PATH, CONTAINER_CLIENTS_PATH}
        or re.fullmatch(
            r"/opt/amnezia/awg/\.p3-next-[0-9a-f]{32}\.(?:conf|clients)", staging
        )
        is None
        or (target == CONTAINER_CONFIG_PATH) != staging.endswith(".conf")
        or isinstance(byte_count, bool)
        or not isinstance(byte_count, int)
        or byte_count < 1
        or byte_count > MAX_COMMAND_BYTES
    ):
        raise ValueError("container writer arguments differ")
    program = (
        "set -euo pipefail; target=$1; stage=$2; count=$3; "
        '[ ! -e "$stage" ]; trap \'rm -f -- "$stage"\' EXIT; '
        'mode=$(stat -c %a -- "$target"); owner=$(stat -c %u:%g -- "$target"); '
        '(umask 077; set -o noclobber; cat >"$stage"); '
        '[ $(stat -c %s -- "$stage") -eq "$count" ]; '
        'chown "$owner" -- "$stage"; chmod "$mode" -- "$stage"; sync -f "$stage" 2>/dev/null || sync; '
        'mv -f -- "$stage" "$target"; trap - EXIT'
    )
    return [
        "/usr/bin/docker",
        "exec",
        "-i",
        container_id,
        "/bin/bash",
        "-c",
        program,
        "p3-writer",
        target,
        staging,
        str(byte_count),
    ]


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
    try:
        resumed = filesystem({"action": "resume", **file_context})
    except Exception as exc:
        raise RuntimeError("ROLLBACK_UNPROVEN: recovery discovery failed") from exc
    if (
        not isinstance(resumed, dict)
        or set(resumed) != {"recovery_state"}
        or not isinstance(resumed["recovery_state"], str)
    ):
        raise RuntimeError("ROLLBACK_UNPROVEN: recovery discovery differs")
    if resumed["recovery_state"]:
        recovery_state = resumed["recovery_state"]
        try:
            recovered = filesystem(
                {"action": "recover", **file_context, "recovery_state": recovery_state}
            )
            if (
                not isinstance(recovered, dict)
                or recovered.get("recovered") is not True
                or set(recovered) != {"recovered", "recovery_syncconf_path"}
                or recovered["recovery_syncconf_path"] != request["syncconf_path"]
            ):
                raise RuntimeError("interrupted recovery differs")
            syncconf(pathlib.Path(recovered["recovery_syncconf_path"]), recovery_state)
            restored = filesystem({"action": "verify-recovery", **file_context})
            _require_rollback_observation(
                restored,
                rollback_expected_observation(request, phase="pre"),
                "recovery",
            )
            cleaned = filesystem(
                {"action": "cleanup", **file_context, "recovery_state": recovery_state}
            )
            if cleaned != {"cleaned": True}:
                raise RuntimeError("recovery cleanup differs")
        except Exception as exc:
            raise RuntimeError(
                "ROLLBACK_UNPROVEN: interrupted recovery failed"
            ) from exc
        raise RuntimeError("RECOVERED_INTERRUPTED: retry requires a new approval")
    inspected = filesystem({"action": "inspect", **file_context})
    _require_rollback_observation(
        inspected, rollback_expected_observation(request, phase="pre"), "pre"
    )
    begun = filesystem({"action": "begin", **file_context})
    if (
        not isinstance(begun, dict)
        or set(begun) != {"recovery_state"}
        or not isinstance(begun.get("recovery_state"), str)
        or not begun["recovery_state"]
    ):
        raise RuntimeError("emergency rollback recovery preparation failed")
    recovery_state = begun["recovery_state"]
    try:
        removed = filesystem(
            {"action": "remove", **file_context, "recovery_state": recovery_state}
        )
        if removed != {"removed": True}:
            raise RuntimeError("candidate removal failed")
        syncconf(pathlib.Path(request["syncconf_path"]), recovery_state)
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
                "recovery_state": recovery_state,
            }
        )
        if cleaned != {"cleaned": True}:
            raise RuntimeError("emergency rollback recovery cleanup differs")
    except Exception as exc:
        try:
            recovered = filesystem(
                {
                    "action": "recover",
                    **file_context,
                    "recovery_state": recovery_state,
                }
            )
            if (
                not isinstance(recovered, dict)
                or set(recovered) != {"recovered", "recovery_syncconf_path"}
                or recovered.get("recovered") is not True
            ):
                raise RuntimeError("emergency rollback recovery failed")
            syncconf(pathlib.Path(recovered["recovery_syncconf_path"]), recovery_state)
            recovery_verified = filesystem(
                {"action": "verify-recovery", **file_context}
            )
            _require_rollback_observation(
                recovery_verified,
                rollback_expected_observation(request, phase="pre"),
                "recovery",
            )
            recovery_cleaned = filesystem(
                {
                    "action": "cleanup",
                    **file_context,
                    "recovery_state": recovery_state,
                }
            )
            if recovery_cleaned != {"cleaned": True}:
                raise RuntimeError("emergency rollback recovery cleanup differs")
        except Exception as recovery_exc:
            raise RuntimeError("ROLLBACK_UNPROVEN") from recovery_exc
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
    return _public_key_fingerprint(values[0])


def _metadata_rows(value: Any) -> tuple[list[dict[str, Any]], str]:
    if not isinstance(value, list):
        raise TypeError("emergency rollback metadata schema differs")
    rows = value
    for row in rows:
        if (
            not isinstance(row, dict)
            or set(row) != {"clientId", "userData"}
            or not isinstance(row.get("clientId"), str)
            or not isinstance(row.get("userData"), dict)
        ):
            raise ValueError("emergency rollback metadata row differs")
    return rows, "list"


def _row_fingerprint(row: dict[str, Any]) -> str:
    key = row.get("clientId")
    if not isinstance(key, str) or not key:
        raise ValueError("emergency rollback metadata key differs")
    return _public_key_fingerprint(key)


class ContainerRollbackFilesystem:
    def __init__(
        self,
        runner: CommandRunner = _default_command_runner,
        stream_runner: StreamCommandRunner = _default_stream_command_runner,
        recovery_root: pathlib.Path = pathlib.Path("/run/home-gateway-p3-peer-guard"),
    ) -> None:
        self.runner = runner
        self.stream_runner = stream_runner
        self.recovery_root = recovery_root
        self.container_id: str | None = None
        self._authorized_sync: tuple[dict[str, Any], str] | None = None

    def _run(self, arguments: Sequence[str], maximum: int = MAX_COMMAND_BYTES) -> bytes:
        return run_checked_command(arguments, runner=self.runner, maximum_bytes=maximum)

    def _resolve_container(self) -> str:
        ids = _read_utf8_lines(
            self._run(
                ["/usr/bin/docker", "ps", "-q", "--filter", "name=^/amnezia-awg2$"]
            ),
            "rollback container",
        )
        names = _read_utf8_lines(
            self._run(["/usr/bin/docker", "ps", "-a", "--format", "{{.Names}}"]),
            "rollback container names",
        )
        if len(ids) != 1 or names.count("amnezia-awg2") != 1:
            raise ValueError("rollback container count differs")
        if self.container_id is not None and self.container_id != ids[0]:
            raise ValueError("rollback container identity changed")
        self.container_id = ids[0]
        return ids[0]

    def _read_container(self, container_id: str, path: str) -> bytes:
        if path not in {CONTAINER_CONFIG_PATH, CONTAINER_CLIENTS_PATH}:
            raise ValueError("rollback container path differs")
        return self._run(["/usr/bin/docker", "exec", container_id, "cat", path])

    def _temporary_bytes(self, container_id: str, path: str) -> bytes | None:
        if re.fullmatch(r"/tmp/[A-Za-z0-9._-]+\.tmp", path) is None:
            raise ValueError("rollback temporary path differs")
        result = self._run(
            [
                "/usr/bin/docker",
                "exec",
                container_id,
                "/bin/bash",
                "-c",
                'if [ -e "$1" ]; then cat -- "$1"; else printf P3_ABSENT; fi',
                "p3-temp-read",
                path,
            ]
        )
        return None if result == b"P3_ABSENT" else result

    def _preflight(self, action: dict[str, Any], container_id: str) -> None:
        stages = container_staging_paths(action["nonce"])
        self._run(
            [
                "/usr/bin/docker",
                "exec",
                container_id,
                "/bin/bash",
                "-c",
                (
                    'set -eu; for p in /bin/bash /usr/bin/awg /usr/bin/awg-quick /usr/bin/cat /usr/bin/mv /usr/bin/stat /usr/bin/sync; do [ -x "$p" ]; done; '
                    '[ -f "$1" ] && [ ! -L "$1" ]; [ -f "$2" ] && [ ! -L "$2" ]; '
                    'shopt -s nullglob; foreign=(/opt/amnezia/awg/.p3-next-*); [ ${#foreign[@]} -eq 0 ]; [ ! -e "$3" ]; [ ! -e "$4" ]'
                ),
                "p3-preflight",
                CONTAINER_CONFIG_PATH,
                CONTAINER_CLIENTS_PATH,
                stages[0],
                stages[1],
            ]
        )

    def _observation(self, action: dict[str, Any]) -> dict[str, Any]:
        container_id = self._resolve_container()
        collector_request = dict(action)
        collector_request["expected_ipv6_policy_sha256"] = action[
            "baseline_ipv6_policy_sha256"
        ]
        snapshot = collect_server_snapshot(collector_request, runner=self.runner)
        if snapshot["container_identity_sha256"] != _sha(container_id.encode("utf-8")):
            raise ValueError("rollback container identity changed")
        prepared = self._run(
            [
                "/usr/bin/docker",
                "exec",
                container_id,
                "/usr/bin/awg-quick",
                "strip",
                CONTAINER_CONFIG_PATH,
            ]
        )
        return {
            "schema": "home-gateway/p3-peer-rollback-observation/v2",
            "candidate_receipt_sha256": action["candidate_receipt_sha256"],
            "candidate_fingerprint_sha256": action["candidate_fingerprint_sha256"],
            "peer_fingerprint_sha256": snapshot["peer_fingerprint_sha256"],
            "peer_set_sha256": snapshot["live_peer_set_sha256"],
            "persistent_config_sha256": snapshot["persistent_config_sha256"],
            "live_peer_set_sha256": snapshot["live_peer_set_sha256"],
            "metadata_sha256": snapshot["metadata_sha256"],
            "temporary_state_sha256": snapshot["temporary_state_sha256"],
            "runtime_identity_sha256": snapshot["runtime_identity_sha256"],
            "prepared_syncconf_sha256": _sha(prepared),
        }

    def _write_backup(self, path: pathlib.Path, data: bytes) -> None:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())

    def _recovery_paths(self, token: str) -> dict[str, pathlib.Path]:
        if re.fullmatch(r"[0-9a-f]{64}", token) is None:
            raise ValueError("emergency rollback recovery state differs")
        prefix = self.recovery_root / (".p3-recovery-" + token)
        return {
            "config": pathlib.Path(str(prefix) + ".conf"),
            "clients": pathlib.Path(str(prefix) + ".clients"),
            "temporary": pathlib.Path(str(prefix) + ".tmp"),
            "new_config": pathlib.Path(str(prefix) + ".new-conf"),
            "new_clients": pathlib.Path(str(prefix) + ".new-clients"),
            "manifest": pathlib.Path(str(prefix) + ".json"),
        }

    def _action_sha256(self, action: dict[str, Any]) -> str:
        return _sha({name: action[name] for name in ROLLBACK_PLAN_KEYS})

    def _load_recovery_state(
        self, action: dict[str, Any], token: str
    ) -> dict[str, Any]:
        paths = self._recovery_paths(token)
        try:
            manifest = json.loads(
                _read_atomic_file(paths["manifest"], MAX_COMMAND_BYTES).decode(
                    "utf-8", errors="strict"
                )
            )
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("emergency rollback recovery manifest differs") from exc
        expected_keys = {
            "schema",
            "recovery_state",
            "action_sha256",
            "container_id",
            "container_identity_sha256",
            "config_backup_sha256",
            "metadata_backup_sha256",
            "temporary_backup_sha256",
            "temporary_present",
            "new_config_sha256",
            "new_metadata_sha256",
        }
        _require_exact_keys(manifest, expected_keys)
        protected_names = ["manifest", "config", "clients", "new_config", "new_clients"]
        if bool(manifest.get("temporary_present")):
            protected_names.append("temporary")
        for name in protected_names:
            item = paths[name].lstat()
            if not stat.S_ISREG(item.st_mode) or stat.S_ISLNK(item.st_mode):
                raise ValueError("emergency rollback recovery file differs")
            if os.name != "nt" and (
                stat.S_IMODE(item.st_mode) != 0o600 or item.st_uid != os.geteuid()
            ):
                raise ValueError("emergency rollback recovery file differs")
        container_id = manifest["container_id"]
        if (
            manifest["schema"] != "home-gateway/p3-peer-rollback-recovery/v2"
            or manifest["recovery_state"] != token
            or manifest["action_sha256"] != self._action_sha256(action)
            or not isinstance(container_id, str)
            or re.fullmatch(r"[A-Za-z0-9._-]{1,128}", container_id) is None
            or manifest["container_identity_sha256"]
            != _sha(container_id.encode("utf-8"))
            or not isinstance(manifest["temporary_present"], bool)
        ):
            raise ValueError("emergency rollback recovery manifest differs")
        for name in (
            "config_backup_sha256",
            "metadata_backup_sha256",
            "temporary_backup_sha256",
            "new_config_sha256",
            "new_metadata_sha256",
        ):
            if not _is_sha256(manifest[name]):
                raise ValueError("emergency rollback recovery manifest differs")
        values = {
            "config": _read_atomic_file(paths["config"], MAX_COMMAND_BYTES),
            "clients": _read_atomic_file(paths["clients"], MAX_COMMAND_BYTES),
            "new_config": _read_atomic_file(paths["new_config"], MAX_COMMAND_BYTES),
            "new_clients": _read_atomic_file(paths["new_clients"], MAX_COMMAND_BYTES),
        }
        if (
            _sha(values["config"]) != manifest["config_backup_sha256"]
            or _sha(values["clients"]) != manifest["metadata_backup_sha256"]
            or _sha(values["new_config"]) != manifest["new_config_sha256"]
            or _sha(values["new_clients"]) != manifest["new_metadata_sha256"]
        ):
            raise ValueError("emergency rollback recovery backup differs")
        if manifest["temporary_present"]:
            values["temporary"] = _read_atomic_file(
                paths["temporary"], MAX_COMMAND_BYTES
            )
            if _sha(values["temporary"]) != manifest["temporary_backup_sha256"]:
                raise ValueError("emergency rollback recovery backup differs")
        else:
            if paths["temporary"].exists() or manifest[
                "temporary_backup_sha256"
            ] != _sha(b"ABSENT"):
                raise ValueError("emergency rollback recovery backup differs")
            values["temporary"] = None
        return {
            "paths": paths,
            "config": values["config"],
            "clients": values["clients"],
            "new_config": values["new_config"],
            "new_clients": values["new_clients"],
            "temporary": values["temporary"],
            "container_id": container_id,
            "temporary_present": manifest["temporary_present"],
        }

    def _cleanup_container_stages(
        self, action: dict[str, Any], container_id: str
    ) -> None:
        config_stage, clients_stage = container_staging_paths(action["nonce"])
        temporary_stage = temporary_recovery_staging_path(action["nonce"])
        self._run(
            [
                "/usr/bin/docker",
                "exec",
                container_id,
                "/bin/bash",
                "-c",
                'rm -f -- "$1" "$2" "$3"; [ ! -e "$1" ] && [ ! -e "$2" ] && [ ! -e "$3" ]',
                "p3-stage-cleanup",
                config_stage,
                clients_stage,
                temporary_stage,
            ]
        )

    def _discover_recovery_state(self, action: dict[str, Any]) -> str | None:
        artifacts = sorted(self.recovery_root.glob(".p3-recovery-*"))
        if not artifacts:
            return None
        tokens: set[str] = set()
        for artifact in artifacts:
            match = re.fullmatch(
                r"\.p3-recovery-([0-9a-f]{64})(?:\.conf|\.clients|\.tmp|\.new-conf|\.new-clients|\.json)",
                artifact.name,
            )
            if match is None:
                raise RuntimeError("ROLLBACK_UNPROVEN: recovery artifact name differs")
            tokens.add(match.group(1))
        if len(tokens) != 1:
            raise RuntimeError(
                "ROLLBACK_UNPROVEN: recovery artifact token count differs"
            )
        token = next(iter(tokens))
        if not self._recovery_paths(token)["manifest"].exists():
            raise RuntimeError("ROLLBACK_UNPROVEN: recovery manifest is absent")
        try:
            self._load_recovery_state(action, token)
        except Exception as exc:
            raise RuntimeError(
                "ROLLBACK_UNPROVEN: recovery artifact set differs"
            ) from exc
        return token

    def _unlink_recovery_path(self, path: pathlib.Path, *, missing_ok: bool) -> None:
        path.unlink(missing_ok=missing_ok)

    def _write_container(
        self, container_id: str, target: str, stage: str, data: bytes
    ) -> None:
        run_checked_stream_command(
            container_writer_arguments(container_id, target, stage, len(data)),
            data,
            runner=self.stream_runner,
        )

    def _write_temporary(
        self, container_id: str, target: str, stage: str, data: bytes
    ) -> None:
        target_match = re.fullmatch(r"/tmp/p3-candidate-([0-9a-f]{32})\.tmp", target)
        stage_match = re.fullmatch(r"/tmp/\.p3-recover-([0-9a-f]{32})\.tmp", stage)
        if (
            target_match is None
            or stage_match is None
            or target_match.group(1) != stage_match.group(1)
            or not data
            or len(data) > MAX_COMMAND_BYTES
        ):
            raise ValueError("rollback temporary recovery differs")
        program = (
            "set -euo pipefail; stage=$1; target=$2; count=$3; umask 077; "
            '[ ! -e "$stage" ]; cat >"$stage"; '
            '[ $(stat -c %s -- "$stage") -eq "$count" ]; '
            'sync -f "$stage" 2>/dev/null || sync; mv -T -- "$stage" "$target"; '
            '[ -f "$target" ] && [ ! -e "$stage" ]'
        )
        run_checked_stream_command(
            [
                "/usr/bin/docker",
                "exec",
                "-i",
                container_id,
                "/bin/bash",
                "-c",
                program,
                "p3-temp-recovery",
                stage,
                target,
                str(len(data)),
            ],
            data,
            runner=self.stream_runner,
        )

    def syncconf(self, path: pathlib.Path, recovery_state: str) -> None:
        if path != pathlib.Path(CONTAINER_CONFIG_PATH) or self._authorized_sync is None:
            raise ValueError("rollback syncconf authorization differs")
        action, authorized_state = self._authorized_sync
        self._authorized_sync = None
        if recovery_state != authorized_state:
            raise ValueError("rollback syncconf authorization differs")
        state = self._load_recovery_state(action, recovery_state)
        container_id = self._resolve_container()
        if state["container_id"] != container_id:
            raise ValueError("rollback container identity changed")
        self._run(
            [
                "/usr/bin/docker",
                "exec",
                container_id,
                "/bin/bash",
                "-c",
                "exec /usr/bin/awg syncconf awg0 <(/usr/bin/awg-quick strip /opt/amnezia/awg/awg0.conf)",
            ]
        )

    def __call__(self, action: dict[str, Any]) -> dict[str, Any]:
        mode = action["action"]
        if mode in {"inspect", "verify", "verify-recovery"}:
            return self._observation(action)
        if mode == "resume":
            token = self._discover_recovery_state(action)
            return {"recovery_state": token or ""}
        if mode == "cleanup":
            state = self._load_recovery_state(action, action["recovery_state"])
            container_id = self._resolve_container()
            if state["container_id"] != container_id:
                raise ValueError("rollback container identity changed")
            self._cleanup_container_stages(action, container_id)
            paths = state["paths"]
            for name in ("config", "clients", "temporary", "new_config", "new_clients"):
                self._unlink_recovery_path(paths[name], missing_ok=True)
            self._unlink_recovery_path(paths["manifest"], missing_ok=False)
            self._authorized_sync = None
            return {"cleaned": True}
        if mode == "recover":
            state = self._load_recovery_state(action, action["recovery_state"])
            container_id = self._resolve_container()
            if state["container_id"] != container_id:
                raise ValueError("rollback container identity changed")
            stages = container_staging_paths(action["nonce"])
            self._cleanup_container_stages(action, container_id)
            self._write_container(
                container_id,
                CONTAINER_CONFIG_PATH,
                stages[0],
                state["config"],
            )
            self._write_container(
                container_id,
                CONTAINER_CLIENTS_PATH,
                stages[1],
                state["clients"],
            )
            temporary = state["temporary"]
            if temporary is not None:
                self._write_temporary(
                    container_id,
                    action["temporary_path"],
                    temporary_recovery_staging_path(action["nonce"]),
                    temporary,
                )
            else:
                self._run(
                    [
                        "/usr/bin/docker",
                        "exec",
                        container_id,
                        "/bin/bash",
                        "-c",
                        'rm -f -- "$1"; [ ! -e "$1" ]',
                        "p3-temp-recovery",
                        action["temporary_path"],
                    ]
                )
            self._authorized_sync = (
                {name: action[name] for name in ROLLBACK_PLAN_KEYS},
                action["recovery_state"],
            )
            return {
                "recovered": True,
                "recovery_syncconf_path": action["syncconf_path"],
            }
        if mode == "remove":
            state = self._load_recovery_state(action, action["recovery_state"])
            container_id = self._resolve_container()
            if state["container_id"] != container_id:
                raise ValueError("rollback container identity changed")
            stages = container_staging_paths(action["nonce"])
            self._write_container(
                container_id, CONTAINER_CONFIG_PATH, stages[0], state["new_config"]
            )
            self._write_container(
                container_id,
                CONTAINER_CLIENTS_PATH,
                stages[1],
                state["new_clients"],
            )
            self._run(
                [
                    "/usr/bin/docker",
                    "exec",
                    container_id,
                    "/bin/bash",
                    "-c",
                    'rm -f -- "$1"; [ ! -e "$1" ]',
                    "p3-temp-remove",
                    action["temporary_path"],
                ]
            )
            self._authorized_sync = (
                {name: action[name] for name in ROLLBACK_PLAN_KEYS},
                action["recovery_state"],
            )
            return {"removed": True}
        if mode != "begin":
            raise ValueError("emergency rollback filesystem action differs")
        container_id = self._resolve_container()
        self._preflight(action, container_id)
        _require_rollback_observation(
            self._observation(action),
            rollback_expected_observation(action, phase="pre"),
            "apply-time pre",
        )
        config = self._read_container(container_id, CONTAINER_CONFIG_PATH)
        clients = self._read_container(container_id, CONTAINER_CLIENTS_PATH)
        prefix, blocks = _config_peer_blocks(config.decode("utf-8", errors="strict"))
        rows, _ = _metadata_rows(json.loads(clients.decode("utf-8", errors="strict")))
        candidate = action["candidate_fingerprint_sha256"]
        matching_blocks = [
            block for block in blocks if _block_fingerprint(block) == candidate
        ]
        matching_rows = [row for row in rows if _row_fingerprint(row) == candidate]
        if len(matching_blocks) != 1 or len(matching_rows) != 1:
            raise ValueError("candidate identity differs before removal")
        new_config = "".join(
            prefix
            + [
                line
                for block in blocks
                if block not in matching_blocks
                for line in block
            ]
        ).encode()
        new_clients = _canonical([row for row in rows if row not in matching_rows])
        self.recovery_root.mkdir(mode=0o700, parents=False, exist_ok=True)
        root_item = self.recovery_root.lstat()
        if not stat.S_ISDIR(root_item.st_mode) or stat.S_ISLNK(root_item.st_mode):
            raise ValueError("emergency rollback recovery root differs")
        if os.name != "nt" and (
            stat.S_IMODE(root_item.st_mode) != 0o700 or root_item.st_uid != os.geteuid()
        ):
            raise ValueError("emergency rollback recovery root differs")
        token = os.urandom(32).hex()
        paths = self._recovery_paths(token)
        created: list[pathlib.Path] = []
        try:
            self._write_backup(paths["config"], config)
            created.append(paths["config"])
            self._write_backup(paths["clients"], clients)
            created.append(paths["clients"])
            temporary = self._temporary_bytes(container_id, action["temporary_path"])
            if temporary is not None:
                self._write_backup(paths["temporary"], temporary)
                created.append(paths["temporary"])
            self._write_backup(paths["new_config"], new_config)
            created.append(paths["new_config"])
            self._write_backup(paths["new_clients"], new_clients)
            created.append(paths["new_clients"])
            recovery_manifest = {
                "schema": "home-gateway/p3-peer-rollback-recovery/v2",
                "recovery_state": token,
                "action_sha256": self._action_sha256(action),
                "container_id": container_id,
                "container_identity_sha256": _sha(container_id.encode()),
                "config_backup_sha256": _sha(config),
                "metadata_backup_sha256": _sha(clients),
                "temporary_backup_sha256": _sha(
                    b"ABSENT" if temporary is None else temporary
                ),
                "temporary_present": temporary is not None,
                "new_config_sha256": _sha(new_config),
                "new_metadata_sha256": _sha(new_clients),
            }
            self._write_backup(paths["manifest"], _canonical(recovery_manifest))
            created.append(paths["manifest"])
            self._load_recovery_state(action, token)
        except Exception:
            for path in reversed(created):
                path.unlink(missing_ok=True)
            raise
        return {"recovery_state": token}


_SYSTEM_ROLLBACK = ContainerRollbackFilesystem()


def _system_atomic_filesystem(action: dict[str, Any]) -> dict[str, Any]:
    return _SYSTEM_ROLLBACK(action)


def _system_syncconf(path: pathlib.Path, recovery_state: str) -> None:
    _SYSTEM_ROLLBACK.syncconf(path, recovery_state)


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


def cli() -> int:
    try:
        return main()
    except (KeyError, OSError, RuntimeError, TypeError, ValueError):
        print('{"error":"P3_GUARD_FAILED"}', file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(cli())
