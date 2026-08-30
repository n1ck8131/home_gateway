#!/usr/bin/env python3
"""Deterministic semantic core for the bounded P3 Amnezia peer guard."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import pathlib
import stat
import time
from collections.abc import Callable
from typing import Any, NamedTuple


class Decision(NamedTuple):
    label: str
    validate: bool
    rollback: bool


PUBLIC_PROTOCOL = {
    "schema": "home-gateway/p3-peer-guard-protocol/v1",
    "flags": [
        "--automatic",
        "--expected-payload-sha256",
        "--expected-protocol-sha256",
        "--json",
    ],
    "receipt_fields": ["payload_sha256", "protocol_sha256", "ready_for_ui"],
}
MAX_PAYLOAD_BYTES = 131072


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def public_protocol_sha256() -> str:
    return hashlib.sha256(_canonical(PUBLIC_PROTOCOL)).hexdigest()


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
    if len(data) != before.st_size or len(data) > MAX_PAYLOAD_BYTES:
        raise ValueError("peer guard payload exceeds its bound")
    return hashlib.sha256(data).hexdigest()


def normalize_runtime(snapshot: dict[str, Any]) -> dict[str, Any]:
    """Remove only reviewed volatile fields and preserve all semantic fields."""
    result = copy.deepcopy(snapshot)
    runtime = result.get("runtime", {})
    for row in runtime.get("iptables", []):
        for name in ("created_at", "packets", "bytes"):
            row.pop(name, None)
    for row in runtime.get("nft", []):
        for name in ("counter_packets", "counter_bytes"):
            row.pop(name, None)
    bindings = []
    for row in runtime.get("bindings", []):
        normalized = {
            key: value for key, value in row.items() if key not in {"recv_q", "send_q"}
        }
        bindings.append(normalized)
    runtime["bindings"] = [
        json.loads(item)
        for item in sorted({_canonical(item).decode("utf-8") for item in bindings})
    ]
    for name in ("iptables", "nft"):
        runtime[name] = sorted(runtime.get(name, []), key=_canonical)
    result["runtime"] = runtime
    return result


def semantic_hash(snapshot: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(normalize_runtime(snapshot))).hexdigest()


def classify_candidate(
    baseline: dict[str, Any], candidate: dict[str, Any], expected_delta: int
) -> Decision:
    baseline_peers = set(baseline.get("peers", []))
    candidate_peers = set(candidate.get("peers", []))
    delta = candidate_peers - baseline_peers
    convergence_fields = (
        "persistent_hash",
        "live_hash",
        "metadata_hash",
        "temporary_hash",
    )
    changed = [baseline.get(name) != candidate.get(name) for name in convergence_fields]
    if any(changed) and not all(changed):
        return Decision("WAIT_CONVERGENCE", False, False)
    if len(delta) != expected_delta or baseline_peers - candidate_peers:
        return Decision("CANDIDATE_DELTA_INVALID", False, False)
    return Decision("CANDIDATE_STABLE", True, False)


def sanitize_failure(
    primary: BaseException, rollback: BaseException | None
) -> dict[str, str]:
    del primary
    result = {"primary_error": "PRIMARY_EXCEPTION"}
    if rollback is not None:
        result["rollback_error"] = "ROLLBACK_EXCEPTION"
    return result


def handle_control_token(token: str, mutate: Callable[[], None]) -> dict[str, str]:
    if token != "AUTO":
        return {"transport_error": "CONTROL_TOKEN_INVALID_OR_EOF"}
    mutate()
    return {"transport": "AUTOMATIC"}


def await_stable(
    observe: Callable[[], dict[str, Any]],
    *,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
    timeout_seconds: int = 180,
) -> dict[str, Any]:
    if timeout_seconds < 5 or timeout_seconds > 180:
        raise ValueError("convergence timeout is outside the bounded contract")
    deadline = monotonic() + timeout_seconds

    def require_before_deadline() -> None:
        if monotonic() >= deadline:
            raise TimeoutError("candidate convergence timed out")

    def bounded_sleep(seconds: float) -> None:
        require_before_deadline()
        if monotonic() + seconds >= deadline:
            raise TimeoutError("candidate convergence timed out")
        sleep(seconds)
        require_before_deadline()

    bounded_sleep(2)
    while True:
        require_before_deadline()
        first = observe()
        require_before_deadline()
        first_hash = semantic_hash(first)
        bounded_sleep(5)
        require_before_deadline()
        second = observe()
        require_before_deadline()
        if semantic_hash(second) == first_hash and _canonical(second) == _canonical(
            first
        ):
            require_before_deadline()
            return second
        bounded_sleep(2)


def candidate_receipt(
    baseline: dict[str, Any], candidate: dict[str, Any], operation: str
) -> dict[str, Any]:
    delta = sorted(set(candidate.get("peers", [])) - set(baseline.get("peers", [])))
    return {
        "schema": "home-gateway/p3-peer-guard-receipt/v1",
        "operation": operation,
        "candidate_count": len(delta),
        "candidate_identity_sha256": hashlib.sha256(_canonical(delta)).hexdigest(),
        "pre_semantic_sha256": semantic_hash(baseline),
        "candidate_semantic_sha256": semantic_hash(candidate),
        "official_ui_rollback_ready": len(delta) == 1,
        "emergency_exact_one_peer_ready": len(delta) == 1,
    }


def execute_emergency_rollback(
    baseline: dict[str, Any],
    candidate: dict[str, Any],
    revalidated: dict[str, Any],
    restored: dict[str, Any],
    *,
    remove_exact: Callable[[str], None],
    syncconf: Callable[[], None],
) -> dict[str, Any]:
    baseline_peers = set(baseline.get("peers", []))
    delta = sorted(set(candidate.get("peers", [])) - baseline_peers)
    if len(delta) != 1 or baseline_peers - set(candidate.get("peers", [])):
        raise ValueError("emergency rollback requires one exact candidate peer")
    if semantic_hash(candidate) != semantic_hash(revalidated):
        raise ValueError("candidate identity changed before rollback")
    remove_exact(delta[0])
    syncconf()
    for name in ("persistent_hash", "live_hash", "metadata_hash", "temporary_hash"):
        if restored.get(name) != baseline.get(name):
            raise RuntimeError("rollback convergence differs")
    if set(restored.get("peers", [])) != baseline_peers or semantic_hash(
        restored
    ) != semantic_hash(baseline):
        raise RuntimeError("rollback semantic runtime differs")
    return {
        "schema": "home-gateway/p3-peer-guard-rollback/v1",
        "candidate_count": 1,
        "one_syncconf": True,
        "restored": True,
    }


def _read_pins(path: pathlib.Path) -> dict[str, Any]:
    if not path.is_file() or path.stat().st_size <= 0 or path.stat().st_size > 65536:
        raise ValueError("runtime pin file is not one bounded regular file")
    pins = json.loads(path.read_text(encoding="utf-8"))
    if pins.get("schema") != "home-gateway/p3-peer-guard-pins/v1":
        raise ValueError("runtime pin schema differs")
    return pins


def _self_test() -> None:
    sample = {"runtime": {"iptables": [], "nft": [], "bindings": []}, "peers": []}
    assert len(semantic_hash(sample)) == 64
    assert (
        handle_control_token("", lambda: None)["transport_error"]
        == "CONTROL_TOKEN_INVALID_OR_EOF"
    )
    assert len(public_protocol_sha256()) == 64


def _valid_sha256(value: str | None) -> bool:
    return (
        value is not None
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pins", type=pathlib.Path)
    parser.add_argument("--validate-only", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--automatic", action="store_true")
    parser.add_argument("--json", action="store_true", dest="json_output")
    parser.add_argument("--expected-payload-sha256")
    parser.add_argument("--expected-protocol-sha256")
    args = parser.parse_args()
    if args.self_test:
        if any(
            (
                args.pins,
                args.validate_only,
                args.automatic,
                args.json_output,
                args.expected_payload_sha256,
                args.expected_protocol_sha256,
            )
        ):
            parser.error("--self-test cannot be combined with another action")
        _self_test()
        return 0
    if args.automatic:
        if (
            args.pins is not None
            or args.validate_only
            or not args.json_output
            or not _valid_sha256(args.expected_payload_sha256)
            or not _valid_sha256(args.expected_protocol_sha256)
        ):
            parser.error("automatic attestation requires the exact JSON hash contract")
        payload_sha256 = own_payload_sha256()
        protocol_sha256 = public_protocol_sha256()
        if payload_sha256 != args.expected_payload_sha256:
            parser.error("peer guard payload identity differs")
        if protocol_sha256 != args.expected_protocol_sha256:
            parser.error("peer guard protocol identity differs")
        print(
            json.dumps(
                {
                    "payload_sha256": payload_sha256,
                    "protocol_sha256": protocol_sha256,
                    "ready_for_ui": True,
                },
                separators=(",", ":"),
            )
        )
        return 0
    if any(
        (
            args.json_output,
            args.expected_payload_sha256,
            args.expected_protocol_sha256,
        )
    ):
        parser.error("attestation flags require --automatic")
    if args.pins is None:
        parser.error("--pins is required")
    _read_pins(args.pins)
    if args.validate_only:
        print('{"schema":"home-gateway/p3-peer-guard-validation/v1","ok":true}')
        return 0
    print("READY_FOR_UI=YES")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
