import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import pathlib
import sys
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "p3-amnezia-peer-guard.py"
SPEC = importlib.util.spec_from_file_location("p3_amnezia_peer_guard", SCRIPT)
guard = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = guard
SPEC.loader.exec_module(guard)

EXPECTED_PROTOCOL = {
    "schema": "home-gateway/p3-peer-guard-protocol/v2",
    "modes": ["attest", "reconcile", "guard", "client-observe", "emergency-rollback"],
    "guard_operations": ["admin", "guest"],
    "events": ["ready_for_ui", "candidate", "stopped"],
    "poll_seconds": 2,
    "stable_seconds": 5,
    "maximum_guard_seconds": 180,
}


def sha(value):
    if not isinstance(value, bytes):
        value = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(value).hexdigest()


def server_snapshot(*, peers=None, classes=None, **changes):
    peers = peers or ["1" * 64]
    classes = classes or {peer: "baseline" for peer in peers}
    result = {
        "container_count": 1,
        "container_running": True,
        "container_identity_sha256": "2" * 64,
        "image_identity_sha256": "3" * 64,
        "container_restart_count": 0,
        "udp_publication_count": 1,
        "udp_publication_sha256": "4" * 64,
        "public_listener_class_count": 2,
        "listener_identity_sha256": "5" * 64,
        "host_policy_loaded": True,
        "host_policy_sha256": "6" * 64,
        "ipv6_non_mutation": True,
        "peer_fingerprint_sha256": list(peers),
        "peer_classes": dict(classes),
        "persistent_peer_set_sha256": sha(sorted(peers)),
        "live_peer_set_sha256": sha(sorted(peers)),
        "metadata_peer_set_sha256": sha(sorted(peers)),
        "candidate_leftover_count": 0,
        "temporary_leftover_count": 0,
        "atomic_leftover_count": 0,
        "firewall_identity_sha256": "7" * 64,
        "payload_sha256": "a" * 64,
        "protocol_sha256": sha(EXPECTED_PROTOCOL),
    }
    result.update(changes)
    return result


def server_identity(snapshot):
    keys = (
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
    return sha({key: snapshot[key] for key in keys})


def reconcile_request(snapshot=None):
    snapshot = snapshot or server_snapshot()
    return {
        "schema": "home-gateway/p3-peer-guard-request/v2",
        "mode": "reconcile",
        "payload_sha256": "a" * 64,
        "protocol_sha256": sha(EXPECTED_PROTOCOL),
        "manifest_sha256": "b" * 64,
        "install_receipt_sha256": "c" * 64,
        "nonce": "d" * 64,
        "expected_container_identity_sha256": snapshot["container_identity_sha256"],
        "expected_image_identity_sha256": snapshot["image_identity_sha256"],
        "expected_udp_publication_sha256": snapshot["udp_publication_sha256"],
        "expected_listener_identity_sha256": snapshot["listener_identity_sha256"],
        "expected_host_policy_sha256": snapshot["host_policy_sha256"],
        "expected_peer_count": len(snapshot["peer_fingerprint_sha256"]),
        "expected_peer_set_sha256": sha(sorted(snapshot["peer_fingerprint_sha256"])),
        "expected_server_baseline_sha256": server_identity(snapshot),
    }


def guard_request(operation="admin", snapshot=None):
    request = reconcile_request(snapshot)
    request["mode"] = "guard"
    request["operation"] = operation
    request["candidate_class"] = operation
    request["maximum_guard_seconds"] = 180
    return request


def client_request(before, after):
    return {
        "schema": "home-gateway/p3-peer-guard-request/v2",
        "mode": "client-observe",
        "payload_sha256": "a" * 64,
        "protocol_sha256": sha(EXPECTED_PROTOCOL),
        "manifest_sha256": "b" * 64,
        "install_receipt_sha256": "c" * 64,
        "nonce": "d" * 64,
        "previous_nonce_sha256": "e" * 64,
        "selected_guest_fingerprint_sha256": "f" * 64,
        "maximum_handshake_age_seconds": 180,
        "expected_before_counter_sha256": sha(before["counter_state"]),
        "expected_after_counter_sha256": sha(after["counter_state"]),
    }


class FakeCollector:
    def __init__(self, *snapshots):
        self.snapshots = [copy.deepcopy(value) for value in snapshots]
        self.requests = []

    def __call__(self, request):
        self.requests.append(copy.deepcopy(request))
        if not self.snapshots:
            raise AssertionError("collector exhausted")
        return copy.deepcopy(self.snapshots.pop(0))


class FakeClock:
    def __init__(self, start=0.0):
        self.now = start
        self.sleeps = []

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


class PeerGuardProtocolTests(unittest.TestCase):
    def test_public_protocol_is_exact_v2(self):
        self.assertEqual(guard.PUBLIC_PROTOCOL, EXPECTED_PROTOCOL)
        self.assertEqual(guard.public_protocol_sha256(), sha(EXPECTED_PROTOCOL))

    def test_read_exact_request_rejects_invalid_utf8_oversize_and_trailing_data(self):
        valid = json.dumps(reconcile_request()).encode()
        self.assertEqual(
            guard.read_exact_request(io.BytesIO(valid)), reconcile_request()
        )
        for value, message in (
            (b"\xff", "UTF-8"),
            (b"x" * 65537, "limit"),
            (valid + b"\n{}", "JSON"),
        ):
            with (
                self.subTest(message=message),
                self.assertRaisesRegex(ValueError, message),
            ):
                guard.read_exact_request(io.BytesIO(value))

    def test_validate_request_rejects_extra_missing_unsupported_and_replayed_nonce(
        self,
    ):
        request = reconcile_request()
        for mutation, message in (
            (lambda value: value.update(extra=True), "schema"),
            (lambda value: value.pop("manifest_sha256"), "schema"),
            (lambda value: value.update(mode="unknown"), "mode"),
        ):
            changed = dict(request)
            mutation(changed)
            with (
                self.subTest(message=message),
                self.assertRaisesRegex(ValueError, message),
            ):
                guard.validate_request(changed.get("mode", "unknown"), changed)
        before = {"counter_state": {"rx": 1, "tx": 2}}
        after = {"counter_state": {"rx": 2, "tx": 4}}
        replay = client_request(before, after)
        replay["previous_nonce_sha256"] = sha(replay["nonce"].encode())
        with self.assertRaisesRegex(ValueError, "replayed nonce"):
            guard.validate_request("client-observe", replay)

    def test_reconcile_returns_only_sanitized_exact_aggregates(self):
        snapshot = server_snapshot(raw_peer="raw-peer", raw_network="172.18.0.1")
        receipt = guard.run_reconcile(
            reconcile_request(snapshot), FakeCollector(snapshot)
        )
        self.assertEqual(receipt["schema"], "home-gateway/p3-peer-reconcile-receipt/v2")
        self.assertEqual(receipt["peer_count"], 1)
        self.assertEqual(receipt["server_baseline_sha256"], server_identity(snapshot))
        encoded = json.dumps(receipt, sort_keys=True)
        for forbidden in ("raw-peer", "172.18.", "docker0", "iptables -A"):
            self.assertNotIn(forbidden, encoded)

    def test_reconcile_rejects_each_mismatched_server_fact(self):
        cases = {
            "container count": {"container_count": 2},
            "container running": {"container_running": False},
            "UDP publication": {"udp_publication_count": 0},
            "host policy": {"host_policy_loaded": False},
            "IPv6": {"ipv6_non_mutation": False},
            "peer set": {"live_peer_set_sha256": "0" * 64},
            "leftover": {"temporary_leftover_count": 1},
            "payload": {"payload_sha256": "0" * 64},
        }
        request = reconcile_request()
        for message, changes in cases.items():
            with (
                self.subTest(message=message),
                self.assertRaisesRegex(ValueError, message),
            ):
                guard.run_reconcile(request, FakeCollector(server_snapshot(**changes)))

    def test_checked_commands_require_allowlist_zero_exit_empty_stderr_and_bound(self):
        ok = guard.run_checked_command(
            ["/usr/bin/docker", "inspect", "synthetic"],
            runner=lambda args, timeout, maximum: guard.CommandResult(0, b"{}", b""),
        )
        self.assertEqual(ok, b"{}")
        for command, result, message in (
            (["docker"], guard.CommandResult(0, b"", b""), "allowlisted"),
            (["/usr/bin/ss"], guard.CommandResult(1, b"", b""), "exit"),
            (["/usr/bin/ss"], guard.CommandResult(0, b"", b"warning"), "stderr"),
            (["/usr/bin/ss"], guard.CommandResult(0, b"x" * 131073, b""), "output"),
        ):
            with (
                self.subTest(message=message),
                self.assertRaisesRegex(ValueError, message),
            ):
                guard.run_checked_command(
                    command, runner=lambda *args, value=result: value
                )


class PeerGuardStreamingTests(unittest.TestCase):
    def candidate(self, operation="admin", fingerprint="8" * 64):
        peers = ["1" * 64, fingerprint]
        classes = {"1" * 64: "baseline", fingerprint: operation}
        return server_snapshot(peers=peers, classes=classes)

    def test_admin_and_guest_require_two_identical_exact_plus_one_snapshots(self):
        for operation in ("admin", "guest"):
            baseline = server_snapshot()
            candidate = self.candidate(operation)
            clock = FakeClock()
            events = list(
                guard.run_guard(
                    operation,
                    guard_request(operation, baseline),
                    FakeCollector(baseline, candidate, candidate),
                    clock,
                )
            )
            self.assertEqual(
                [event["event"] for event in events], ["ready_for_ui", "candidate"]
            )
            self.assertEqual(events[-1]["candidate_count"], 1)
            self.assertTrue(events[-1]["persistent_live_metadata_equal"])
            self.assertEqual(clock.sleeps, [2, 5])

    def test_partial_convergence_waits_then_accepts_stable_candidate(self):
        baseline = server_snapshot()
        candidate = self.candidate()
        partial = copy.deepcopy(candidate)
        partial["live_peer_set_sha256"] = baseline["live_peer_set_sha256"]
        clock = FakeClock()
        events = list(
            guard.run_guard(
                "admin",
                guard_request("admin", baseline),
                FakeCollector(baseline, partial, candidate, candidate),
                clock,
            )
        )
        self.assertEqual(events[-1]["event"], "candidate")
        self.assertEqual(clock.sleeps, [2, 2, 5])

    def test_unknown_removal_or_metadata_class_emits_sanitized_stopped(self):
        baseline = server_snapshot()
        removed = server_snapshot(peers=["9" * 64], classes={"9" * 64: "admin"})
        events = list(
            guard.run_guard(
                "admin",
                guard_request("admin", baseline),
                FakeCollector(baseline, removed),
                FakeClock(),
            )
        )
        self.assertEqual(events[-1]["event"], "stopped")
        self.assertEqual(events[-1]["reason"], "DELTA_INVALID")
        self.assertNotIn("9" * 64, json.dumps(events))

    def test_changing_candidate_stops_at_exact_deadline(self):
        baseline = server_snapshot()
        first = self.candidate(fingerprint="8" * 64)
        second = self.candidate(fingerprint="9" * 64)
        clock = FakeClock(start=100.0)
        collector = FakeCollector(baseline, *([first, second] * 30))
        request = guard_request("admin", baseline)
        request["maximum_guard_seconds"] = 12
        events = list(guard.run_guard("admin", request, collector, clock))
        self.assertEqual(events[-1]["event"], "stopped")
        self.assertEqual(events[-1]["reason"], "TIMEOUT")
        self.assertLessEqual(clock.now, 112.0)


class ClientObserveAndRollbackTests(unittest.TestCase):
    def client_states(self):
        before = {
            "selected_guest_fingerprint_sha256": "f" * 64,
            "selected_guest_match": True,
            "handshake_age_seconds": 20,
            "counter_state": {"rx": 10, "tx": 5},
        }
        after = {
            "selected_guest_fingerprint_sha256": "f" * 64,
            "selected_guest_match": True,
            "handshake_age_seconds": 1,
            "counter_state": {"rx": 12, "tx": 9},
        }
        return before, after

    def test_client_observation_is_nonce_bound_and_proves_counter_delta(self):
        before, after = self.client_states()
        clock = FakeClock()
        receipt = guard.run_client_observe(
            client_request(before, after), FakeCollector(before, after), clock
        )
        self.assertEqual(receipt["schema"], "home-gateway/p3-peer-client-observe/v2")
        self.assertEqual(receipt["nonce_sha256"], sha(("d" * 64).encode()))
        self.assertTrue(receipt["selected_guest_match"])
        self.assertTrue(receipt["handshake_fresh"])
        self.assertTrue(receipt["traffic_delta"])
        self.assertEqual(receipt["observation_duration_seconds"], 10)
        self.assertEqual(clock.sleeps, [10])

    def test_client_observation_rejects_identity_freshness_counter_and_delta_mismatch(
        self,
    ):
        before, after = self.client_states()
        cases = []
        wrong_selected = copy.deepcopy(after)
        wrong_selected["selected_guest_match"] = False
        cases.append((before, wrong_selected, "selected Guest"))
        stale = copy.deepcopy(after)
        stale["handshake_age_seconds"] = 181
        cases.append((before, stale, "handshake"))
        no_delta = copy.deepcopy(after)
        no_delta["counter_state"] = before["counter_state"]
        cases.append((before, no_delta, "counter"))
        for first, second, message in cases:
            with (
                self.subTest(message=message),
                self.assertRaisesRegex(ValueError, message),
            ):
                guard.run_client_observe(
                    client_request(before, after),
                    FakeCollector(first, second),
                    FakeClock(),
                )

    def rollback_request(self):
        return {
            "schema": "home-gateway/p3-peer-guard-request/v2",
            "mode": "emergency-rollback",
            "payload_sha256": "a" * 64,
            "protocol_sha256": sha(EXPECTED_PROTOCOL),
            "manifest_sha256": "b" * 64,
            "install_receipt_sha256": "c" * 64,
            "nonce": "d" * 64,
            "candidate_receipt_sha256": "8" * 64,
            "rollback_plan_sha256": "9" * 64,
            "confirmation": "P3-EMERGENCY-ROLLBACK-0123456789ABCDEF",
            "candidate_fingerprint_sha256": "f" * 64,
            "persistent_config_path": "/opt/amnezia/awg/wg0.conf",
            "metadata_path": "/opt/amnezia/awg/peers.json",
            "temporary_path": "/run/home-gateway-p3-peer-guard/candidate.tmp",
            "syncconf_path": "/run/home-gateway-p3-peer-guard/awg.conf",
        }

    def test_emergency_rollback_is_exact_candidate_bound_and_one_syncconf(self):
        calls = []

        def filesystem(action):
            calls.append((action["action"], action.get("candidate_fingerprint_sha256")))
            if action["action"] == "inspect":
                return {"exact_plus_one": True, "candidate_unchanged": True}
            if action["action"] == "verify":
                return {"restored": True, "temporary_leftover_count": 0}
            return {"removed": True}

        receipt = guard.run_emergency_rollback(
            self.rollback_request(),
            filesystem,
            lambda path: calls.append(("syncconf", str(path))),
        )
        self.assertTrue(receipt["restored"])
        self.assertEqual(
            [name for name, _ in calls], ["inspect", "remove", "syncconf", "verify"]
        )

    def test_emergency_rollback_revalidates_before_any_mutation(self):
        calls = []
        with self.assertRaisesRegex(ValueError, "candidate"):
            guard.run_emergency_rollback(
                self.rollback_request(),
                lambda action: (
                    calls.append(action)
                    or {"exact_plus_one": False, "candidate_unchanged": True}
                ),
                lambda path: calls.append(path),
            )
        self.assertEqual(len(calls), 1)

    def test_main_dispatches_client_and_emergency_modes_to_fixed_adapters(self):
        before, after = self.client_states()
        client = client_request(before, after)
        client_receipt = {"schema": "home-gateway/p3-peer-client-observe/v2"}
        with (
            contextlib.redirect_stdout(io.StringIO()),
            mock.patch.object(sys, "argv", [str(SCRIPT), "client-observe"]),
            mock.patch.object(guard, "read_exact_request", return_value=client),
            mock.patch.object(
                guard, "run_client_observe", return_value=client_receipt
            ) as observe,
        ):
            self.assertEqual(guard.main(), 0)
        observe.assert_called_once()
        self.assertIs(observe.call_args.args[1], guard._system_client_collector)

        rollback = self.rollback_request()
        rollback_receipt = {"schema": "home-gateway/p3-peer-emergency-rollback/v2"}
        with (
            contextlib.redirect_stdout(io.StringIO()),
            mock.patch.object(sys, "argv", [str(SCRIPT), "emergency-rollback"]),
            mock.patch.object(guard, "read_exact_request", return_value=rollback),
            mock.patch.object(
                guard, "run_emergency_rollback", return_value=rollback_receipt
            ) as emergency,
        ):
            self.assertEqual(guard.main(), 0)
        emergency.assert_called_once()
        self.assertIs(emergency.call_args.args[1], guard._system_atomic_filesystem)
        self.assertIs(emergency.call_args.args[2], guard._system_syncconf)


if __name__ == "__main__":
    unittest.main()
