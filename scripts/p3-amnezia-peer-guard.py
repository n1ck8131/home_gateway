#!/usr/bin/env python3
"""Deterministic semantic core for the bounded P3 Amnezia peer guard."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import pathlib
import time
from collections.abc import Callable
from typing import Any, NamedTuple


class Decision(NamedTuple):
    label: str
    validate: bool
    rollback: bool


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


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
    timeout_seconds: int = 180,
) -> dict[str, Any]:
    if timeout_seconds < 5 or timeout_seconds > 180:
        raise ValueError("convergence timeout is outside the bounded contract")
    elapsed = 0
    sleep(2)
    elapsed += 2
    while elapsed <= timeout_seconds:
        first = observe()
        first_hash = semantic_hash(first)
        sleep(5)
        elapsed += 5
        second = observe()
        if semantic_hash(second) == first_hash and _canonical(second) == _canonical(
            first
        ):
            return second
        sleep(2)
        elapsed += 2
    raise TimeoutError("candidate convergence timed out")


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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pins", type=pathlib.Path)
    parser.add_argument("--validate-only", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        _self_test()
        return 0
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
