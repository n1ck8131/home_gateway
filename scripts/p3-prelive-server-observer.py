#!/usr/bin/env python3
"""Sanitized, read-only P3 prerequisite observer framing contract."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
from typing import Any, BinaryIO

MAX_FRAME_BYTES = 524288
SERVER_BASELINE_KEYS = (
    "atomic_leftover_count",
    "candidate_leftover_count",
    "container_count",
    "container_identity_sha256",
    "container_restart_count",
    "container_running",
    "firewall_identity_sha256",
    "host_policy_loaded",
    "host_policy_sha256",
    "image_identity_sha256",
    "ipv6_non_mutation",
    "ipv6_policy_sha256",
    "listener_identity_sha256",
    "live_peer_set_sha256",
    "metadata_peer_set_sha256",
    "metadata_sha256",
    "payload_sha256",
    "peer_fingerprint_sha256",
    "persistent_config_sha256",
    "persistent_peer_set_sha256",
    "protocol_sha256",
    "public_listener_class_count",
    "runtime_identity_sha256",
    "temporary_leftover_count",
    "temporary_state_sha256",
    "udp_publication_count",
    "udp_publication_sha256",
)


def _sha(value: Any) -> str:
    if not isinstance(value, bytes):
        value = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(value).hexdigest()


def _is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def validate_server_baseline(baseline: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(baseline, dict) or set(baseline) != set(SERVER_BASELINE_KEYS):
        raise ValueError("server baseline schema differs")
    for name in (
        "container_count",
        "container_restart_count",
        "public_listener_class_count",
        "temporary_leftover_count",
        "candidate_leftover_count",
        "atomic_leftover_count",
        "udp_publication_count",
    ):
        if isinstance(baseline[name], bool) or not isinstance(baseline[name], int):
            raise TypeError(f"server baseline {name} type differs")
    for name in ("container_running", "host_policy_loaded", "ipv6_non_mutation"):
        if not isinstance(baseline[name], bool):
            raise TypeError(f"server baseline {name} type differs")
    hashes = set(SERVER_BASELINE_KEYS) - {
        "container_count",
        "container_restart_count",
        "container_running",
        "host_policy_loaded",
        "ipv6_non_mutation",
        "peer_fingerprint_sha256",
        "public_listener_class_count",
        "temporary_leftover_count",
        "candidate_leftover_count",
        "atomic_leftover_count",
        "udp_publication_count",
    }
    if any(not _is_sha256(baseline[name]) for name in hashes):
        raise ValueError("server baseline hash differs")
    peers = baseline["peer_fingerprint_sha256"]
    if (
        not isinstance(peers, list)
        or len(peers) > 1024
        or len(peers) != len(set(peers))
        or any(not _is_sha256(peer) for peer in peers)
    ):
        raise ValueError("server baseline peers differ")
    peer_hash = _sha(sorted(peers))
    if any(
        baseline[name] != peer_hash
        for name in (
            "persistent_peer_set_sha256",
            "live_peer_set_sha256",
            "metadata_peer_set_sha256",
        )
    ):
        raise ValueError("server baseline convergence differs")
    if (
        baseline["container_count"] != 1
        or baseline["container_running"] is not True
        or baseline["container_restart_count"] < 0
        or baseline["udp_publication_count"] != 1
        or baseline["public_listener_class_count"] < 1
        or baseline["host_policy_loaded"] is not True
        or baseline["ipv6_non_mutation"] is not True
        or any(
            baseline[name] != 0
            for name in (
                "candidate_leftover_count",
                "temporary_leftover_count",
                "atomic_leftover_count",
            )
        )
    ):
        raise ValueError("server baseline facts differ")
    result = dict(baseline)
    result["peer_fingerprint_sha256"] = sorted(peers)
    return result


def server_baseline_sha256(baseline: dict[str, Any]) -> str:
    return _sha(validate_server_baseline(baseline))


def encode_attested_frame(
    payload: bytes,
    nonce: str,
    protocol_sha256: str,
    expected_ipv6_policy_sha256: str,
) -> bytes:
    if not isinstance(payload, bytes) or not payload or len(payload) > MAX_FRAME_BYTES:
        raise ValueError("observer payload length differs")
    if not _is_sha256(nonce):
        raise ValueError("observer nonce differs")
    if not _is_sha256(protocol_sha256):
        raise ValueError("observer protocol differs")
    if not _is_sha256(expected_ipv6_policy_sha256):
        raise ValueError("observer IPv6 policy differs")
    header = {
        "expected_ipv6_policy_sha256": expected_ipv6_policy_sha256,
        "length": len(payload),
        "nonce": nonce,
        "payload_sha256": _sha(payload),
        "protocol_sha256": protocol_sha256,
        "schema": "home-gateway/p3-prelive-observer-frame/v1",
    }
    return (
        json.dumps(header, sort_keys=True, separators=(",", ":")).encode()
        + b"\n"
        + payload
    )


def read_attested_frame(
    stream: BinaryIO,
    expected_nonce: str,
    expected_protocol_sha256: str,
    expected_ipv6_policy_sha256: str,
) -> bytes:
    raw = stream.read(MAX_FRAME_BYTES + 2049)
    if len(raw) > MAX_FRAME_BYTES + 2048 or b"\n" not in raw:
        raise TypeError("observer frame length differs")
    header_raw, payload = raw.split(b"\n", 1)
    try:
        header = json.loads(header_raw.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("observer frame header differs") from exc
    if not isinstance(header, dict) or set(header) != {
        "expected_ipv6_policy_sha256",
        "length",
        "nonce",
        "payload_sha256",
        "protocol_sha256",
        "schema",
    }:
        raise ValueError("observer frame header differs")
    if header["schema"] != "home-gateway/p3-prelive-observer-frame/v1":
        raise ValueError("observer frame schema differs")
    if header["nonce"] != expected_nonce:
        raise ValueError("observer frame nonce differs")
    if header["protocol_sha256"] != expected_protocol_sha256:
        raise ValueError("observer frame protocol differs")
    if header["expected_ipv6_policy_sha256"] != expected_ipv6_policy_sha256:
        raise ValueError("observer frame IPv6 policy differs")
    if not isinstance(header["length"], int) or isinstance(header["length"], bool):
        raise TypeError("observer frame length differs")
    if len(payload) < header["length"]:
        raise ValueError("observer frame length differs")
    if len(payload) > header["length"]:
        raise ValueError("observer frame trailing data differs")
    if _sha(payload) != header["payload_sha256"]:
        raise ValueError("observer frame hash differs")
    return payload


def build_observation_receipt(
    baseline: dict[str, Any], *, payload_sha256: str, protocol_sha256: str, nonce: str
) -> dict[str, Any]:
    if not all(_is_sha256(value) for value in (payload_sha256, protocol_sha256, nonce)):
        raise ValueError("observer receipt identity differs")
    validated = validate_server_baseline(baseline)
    if (
        validated["payload_sha256"] != payload_sha256
        or validated["protocol_sha256"] != protocol_sha256
    ):
        raise ValueError("observer receipt payload differs")
    return {
        "live_mutation_performed": False,
        "nonce_sha256": _sha(nonce.encode()),
        "payload_sha256": payload_sha256,
        "protocol_sha256": protocol_sha256,
        "raw_identity_exposed": False,
        "schema": "home-gateway/p3-prelive-server-observation/v1",
        "server_baseline": validated,
        "server_baseline_sha256": server_baseline_sha256(validated),
    }


def read_only_command_contract(container_id: str) -> list[list[str]]:
    if not isinstance(container_id, str) or not container_id:
        raise ValueError("observer container differs")
    return [
        ["/usr/bin/docker", "inspect", container_id],
        ["/usr/bin/docker", "image", "inspect", "<image-id>"],
        ["/usr/bin/docker", "port", container_id, "38556/udp"],
        ["/usr/bin/docker", "exec", container_id, "cat", "/opt/amnezia/awg/awg0.conf"],
        [
            "/usr/bin/docker",
            "exec",
            container_id,
            "cat",
            "/opt/amnezia/awg/clientsTable",
        ],
        [
            "/usr/bin/docker",
            "exec",
            container_id,
            "/usr/bin/awg",
            "show",
            "awg0",
            "peers",
        ],
        ["/usr/bin/ss", "-H", "-lntu"],
        ["/usr/sbin/iptables-save"],
        ["/usr/sbin/ip6tables-save"],
        ["/usr/sbin/nft", "list", "ruleset"],
        ["/usr/bin/systemctl", "is-active", "home-gateway-docker-policy.service"],
    ]


def _self_test() -> None:
    payload = b"observer"
    nonce = "1" * 64
    protocol = "2" * 64
    ipv6 = "3" * 64
    assert (
        read_attested_frame(
            io.BytesIO(encode_attested_frame(payload, nonce, protocol, ipv6)),
            nonce,
            protocol,
            ipv6,
        )
        == payload
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if not args.self_test:
        parser.error("one explicit offline-safe action is required")
    _self_test()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
