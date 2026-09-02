import base64
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "p3-amnezia-peer-guard.py"
SPEC = importlib.util.spec_from_file_location("p3_amnezia_peer_guard", SCRIPT)
guard = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = guard
SPEC.loader.exec_module(guard)
PAYLOAD = guard.own_payload_sha256()

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


def server_snapshot(*, peers=None, **changes):
    peers = peers or ["1" * 64]
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
        "ipv6_policy_sha256": "8" * 64,
        "peer_fingerprint_sha256": list(peers),
        "persistent_peer_set_sha256": sha(sorted(peers)),
        "live_peer_set_sha256": sha(sorted(peers)),
        "metadata_peer_set_sha256": sha(sorted(peers)),
        "persistent_config_sha256": "9" * 64,
        "metadata_sha256": "a" * 64,
        "temporary_state_sha256": "b" * 64,
        "runtime_identity_sha256": "c" * 64,
        "candidate_leftover_count": 0,
        "temporary_leftover_count": 0,
        "atomic_leftover_count": 0,
        "firewall_identity_sha256": "7" * 64,
        "payload_sha256": PAYLOAD,
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
    return sha({key: snapshot[key] for key in keys})


def reconcile_request(snapshot=None):
    snapshot = snapshot or server_snapshot()
    return {
        "schema": "home-gateway/p3-peer-guard-request/v2",
        "mode": "reconcile",
        "payload_sha256": PAYLOAD,
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
        "expected_firewall_identity_sha256": snapshot["firewall_identity_sha256"],
        "expected_ipv6_policy_sha256": snapshot["ipv6_policy_sha256"],
        "persistent_config_path": "/opt/amnezia/awg/awg0.conf",
        "metadata_path": "/opt/amnezia/awg/clientsTable",
        "temporary_path": "/tmp",
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
        "payload_sha256": PAYLOAD,
        "protocol_sha256": sha(EXPECTED_PROTOCOL),
        "manifest_sha256": "b" * 64,
        "install_receipt_sha256": "c" * 64,
        "nonce": "d" * 64,
        "previous_nonce_sha256": "e" * 64,
        "selected_guest_fingerprint_sha256": "f" * 64,
        "maximum_handshake_age_seconds": 180,
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


class FakeContainerRollbackFilesystem(guard.ContainerRollbackFilesystem):
    def __init__(self, recovery_root, *, fail_write_number=None, fail_temporary=False):
        super().__init__(
            runner=lambda *args, **kwargs: None,
            stream_runner=lambda *args, **kwargs: None,
            recovery_root=recovery_root,
        )
        public_key_bytes = b"x" * 32
        public_key = base64.b64encode(public_key_bytes).decode()
        self.candidate = sha(public_key_bytes)
        self.config = (
            "[Interface]\nAddress = 10.0.0.1\n[Peer]\nPublicKey = " + public_key + "\n"
        ).encode()
        self.clients = json.dumps(
            [{"clientId": public_key, "userData": {"name": "synthetic"}}],
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        self.temporary = b"synthetic-candidate-temp"
        self.events = []
        self.fail_write_number = fail_write_number
        self.fail_temporary = fail_temporary
        self.write_count = 0

    def _resolve_container(self):
        self.container_id = "synthetic-container-id"
        return self.container_id

    def _preflight(self, action, container_id):
        self.events.append("preflight")

    def _observation(self, action):
        return guard.rollback_expected_observation(action, phase="pre")

    def _read_container(self, container_id, path):
        return self.config if path == guard.CONTAINER_CONFIG_PATH else self.clients

    def _temporary_bytes(self, container_id, path):
        return self.temporary

    def _write_container(self, container_id, target, stage, data):
        self.write_count += 1
        self.events.append(("write", target, stage))
        if self.write_count == self.fail_write_number:
            raise RuntimeError("synthetic interrupted container write")
        if target == guard.CONTAINER_CONFIG_PATH:
            self.config = data
        else:
            self.clients = data

    def _write_temporary(self, container_id, target, stage, data):
        self.events.append(("temp", target, stage))
        if self.fail_temporary:
            raise RuntimeError("synthetic interrupted temporary write")
        self.temporary = data

    def _run(self, arguments, maximum=guard.MAX_COMMAND_BYTES):
        self.events.append(("run", tuple(arguments)))
        return b""


class CleanupCrashContainerRollbackFilesystem(FakeContainerRollbackFilesystem):
    def __init__(self, recovery_root, fail_cleanup_number):
        super().__init__(recovery_root)
        self.fail_cleanup_number = fail_cleanup_number
        self.cleanup_count = 0

    def _unlink_recovery_path(self, path, *, missing_ok):
        self.cleanup_count += 1
        result = super()._unlink_recovery_path(path, missing_ok=missing_ok)
        if self.cleanup_count == self.fail_cleanup_number:
            raise OSError("synthetic cleanup interruption")
        return result


class PeerGuardProtocolTests(unittest.TestCase):
    def test_golden_baseline_v2_hash_is_stable(self):
        fixture = json.loads(
            (ROOT / "tests" / "fixtures" / "p3" / "server-baseline-v2.json").read_text()
        )
        self.assertEqual(len(fixture), 27)
        self.assertEqual(
            guard.server_baseline_sha256(fixture),
            "68943c7693ed9a442b206749572dc44e2e44a595af080e254836f29ff73ebb1f",
        )

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

    def test_every_mode_rejects_installed_payload_drift_before_dispatch(self):
        before = {"counter_state": {"rx": 1, "tx": 2}}
        after = {"counter_state": {"rx": 2, "tx": 4}}
        requests = {
            "attest": {
                key: reconcile_request()[key] for key in guard.COMMON_REQUEST_KEYS
            },
            "reconcile": reconcile_request(),
            "guard": guard_request(),
            "client-observe": client_request(before, after),
            "emergency-rollback": ClientObserveAndRollbackTests().rollback_request(),
        }
        requests["attest"]["mode"] = "attest"
        with mock.patch.object(guard, "own_payload_sha256", return_value="0" * 64):
            for mode, request in requests.items():
                with (
                    self.subTest(mode=mode),
                    self.assertRaisesRegex(ValueError, "payload"),
                ):
                    guard.validate_request(mode, request)

    def test_reconcile_returns_only_sanitized_exact_aggregates(self):
        snapshot = server_snapshot()
        receipt = guard.run_reconcile(
            reconcile_request(snapshot), FakeCollector(snapshot)
        )
        self.assertEqual(receipt["schema"], "home-gateway/p3-peer-reconcile-receipt/v2")
        self.assertEqual(receipt["peer_count"], 1)
        self.assertEqual(receipt["server_baseline_sha256"], server_identity(snapshot))
        encoded = json.dumps(receipt, sort_keys=True)
        for forbidden in ("raw-peer", "172.18.", "docker0", "iptables -A"):
            self.assertNotIn(forbidden, encoded)

    def test_reconcile_requires_the_exact_27_field_baseline_contract(self):
        snapshot = server_snapshot()
        self.assertEqual(set(snapshot), set(guard.SERVER_BASELINE_KEYS))
        self.assertNotIn("prepared_syncconf_sha256", snapshot)
        receipt = guard.run_reconcile(
            reconcile_request(snapshot), FakeCollector(snapshot)
        )
        self.assertEqual(receipt["server_baseline_sha256"], server_identity(snapshot))

        mutations = []
        missing = copy.deepcopy(snapshot)
        missing.pop("persistent_config_sha256")
        mutations.append(missing)
        extra = copy.deepcopy(snapshot)
        extra["prepared_syncconf_sha256"] = "0" * 64
        mutations.append(extra)
        wrong_type = copy.deepcopy(snapshot)
        wrong_type["container_restart_count"] = "0"
        mutations.append(wrong_type)
        malformed_hash = copy.deepcopy(snapshot)
        malformed_hash["metadata_sha256"] = "not-a-hash"
        mutations.append(malformed_hash)
        wrong_count = copy.deepcopy(snapshot)
        wrong_count["public_listener_class_count"] = 0
        mutations.append(wrong_count)
        wrong_boolean = copy.deepcopy(snapshot)
        wrong_boolean["container_running"] = 1
        mutations.append(wrong_boolean)

        for changed in mutations:
            with (
                self.subTest(changed=changed),
                self.assertRaises((TypeError, ValueError)),
            ):
                guard.run_reconcile(reconcile_request(snapshot), FakeCollector(changed))

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

    def test_nft_ruleset_allows_only_bounded_iptables_nft_compat_warnings(self):
        warning = (
            b"# Warning: table ip filter is managed by iptables-nft, do not touch!\n"
            b"# Warning: table ip6 nat is managed by iptables-nft, do not touch!\n"
        )
        output = b"table ip filter { counter packets 17 bytes 99 }\n"

        self.assertEqual(
            guard.run_nft_ruleset_command(
                runner=lambda *_args: guard.CommandResult(0, output, warning)
            ),
            output,
        )
        for stderr in (
            warning + b"unexpected\n",
            warning.replace(b"table ip ", b"table inet ", 1),
            warning.replace(b"\n", b"\r\n", 1),
            warning * 31,
        ):
            with (
                self.subTest(stderr_sha256=sha(stderr)),
                self.assertRaisesRegex(ValueError, "stderr"),
            ):
                guard.run_nft_ruleset_command(
                    runner=lambda *_args, value=stderr: guard.CommandResult(
                        0, output, value
                    )
                )

        for result, message in (
            (guard.CommandResult(1, output, warning), "exit"),
            (guard.CommandResult(0, output, warning, overflowed=True), "output"),
            (guard.CommandResult(0, output, warning, timed_out=True), "timeout"),
        ):
            with (
                self.subTest(message=message),
                self.assertRaisesRegex(ValueError, message),
            ):
                guard.run_nft_ruleset_command(runner=lambda *_args, value=result: value)

    def test_system_collector_uses_independent_persistent_live_metadata_and_temp_sources(
        self,
    ):
        public_bytes = bytes(range(32))
        public_key = base64.b64encode(public_bytes).decode()
        fingerprint = sha(public_bytes)
        ipv4 = b"*filter\nCOMMIT\n"
        ipv6 = b"*filter\nCOMMIT\n"
        nft = b"table inet filter { counter packets 17 bytes 99 }\n"
        config = f"[Interface]\nPrivateKey = omitted\n[Peer]\nPublicKey = {public_key}\n".encode()
        clients = json.dumps(
            [{"clientId": public_key, "userData": {"clientName": "renamed freely"}}],
            separators=(",", ":"),
        ).encode()
        outputs = {
            (
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
            ): b'{"ID":"container-id","Image":"image-ref","Names":"amnezia-awg2","State":"running"}\n',
            (
                "/usr/bin/docker",
                "inspect",
                "container-id",
            ): b'[{"Id":"container-id","Image":"image-id","Name":"/amnezia-awg2","RestartCount":0,"State":{"Running":true,"Restarting":false},"HostConfig":{"RestartPolicy":{"Name":"unless-stopped"}}}]',
            (
                "/usr/bin/docker",
                "image",
                "inspect",
                "image-id",
            ): b'[{"Id":"image-id","RepoDigests":["repo@example.invalid/digest"]}]',
            (
                "/usr/bin/docker",
                "port",
                "container-id",
                "38556/udp",
            ): b"0.0.0.0:38556\n[::]:38556\n",
            (
                "/usr/bin/docker",
                "exec",
                "container-id",
                "cat",
                "/opt/amnezia/awg/awg0.conf",
            ): config,
            (
                "/usr/bin/docker",
                "exec",
                "container-id",
                "cat",
                "/opt/amnezia/awg/clientsTable",
            ): clients,
            (
                "/usr/bin/docker",
                "exec",
                "container-id",
                "/usr/bin/awg",
                "show",
                "awg0",
                "peers",
            ): (public_key + "\n").encode(),
            (
                "/usr/bin/docker",
                "exec",
                "container-id",
                "/bin/bash",
                "-c",
                'shopt -s nullglob; for f in /tmp/*.tmp; do [ -f "$f" ] && printf \'%s\\0\' "${f##*/}"; done',
            ): b"",
            ("/usr/bin/ss", "-H", "-lntu"): b"udp UNCONN 0 0 0.0.0.0:38556 0.0.0.0:*\n",
            ("/usr/sbin/iptables-save",): ipv4,
            ("/usr/sbin/ip6tables-save",): ipv6,
            ("/usr/sbin/nft", "list", "ruleset"): nft,
            (
                "/usr/bin/systemctl",
                "is-active",
                "netfilter-persistent.service",
            ): b"active\n",
            (
                "/usr/bin/systemctl",
                "is-active",
                "home-gateway-docker-policy.service",
            ): b"active\n",
        }
        seen = []

        def runner(arguments, _timeout, _maximum):
            key = tuple(arguments)
            seen.append(key)
            stderr = (
                b"# Warning: table ip filter is managed by iptables-nft, do not touch!\n"
                if key == ("/usr/sbin/nft", "list", "ruleset")
                else b""
            )
            return guard.CommandResult(0, outputs[key], stderr)

        request = reconcile_request()
        request["expected_ipv6_policy_sha256"] = guard.normalized_policy_sha256(ipv6)
        snapshot = guard.collect_server_snapshot(request, runner=runner)
        self.assertEqual(snapshot["peer_fingerprint_sha256"], [fingerprint])
        self.assertEqual(snapshot["persistent_peer_set_sha256"], sha([fingerprint]))
        self.assertEqual(snapshot["live_peer_set_sha256"], sha([fingerprint]))
        self.assertEqual(snapshot["metadata_peer_set_sha256"], sha([fingerprint]))
        self.assertEqual(snapshot["persistent_config_sha256"], sha(config))
        self.assertEqual(snapshot["metadata_sha256"], sha(clients))
        self.assertTrue(snapshot["ipv6_non_mutation"])
        self.assertEqual(snapshot["temporary_leftover_count"], 0)
        self.assertNotIn(("/usr/bin/awg", "show", "all", "public-keys"), seen)
        self.assertIn(
            (
                "/usr/bin/systemctl",
                "is-active",
                "home-gateway-docker-policy.service",
            ),
            seen,
        )
        self.assertNotIn(
            (
                "/usr/bin/systemctl",
                "is-active",
                "netfilter-persistent.service",
            ),
            seen,
        )
        self.assertTrue(
            all(
                "/opt/amnezia/awg/wg0.conf" != argument
                for call in seen
                for argument in call
            )
        )

    def test_cli_sanitizes_system_adapter_schema_exceptions_without_traceback(self):
        request = reconcile_request()
        stderr = io.StringIO()
        with (
            contextlib.redirect_stderr(stderr),
            mock.patch.object(sys, "argv", [str(SCRIPT), "reconcile"]),
            mock.patch.object(guard, "read_exact_request", return_value=request),
            mock.patch.object(guard, "_system_collector", side_effect=KeyError("raw")),
        ):
            self.assertEqual(guard.cli(), 1)
        self.assertEqual(stderr.getvalue().strip(), '{"error":"P3_GUARD_FAILED"}')


class PeerGuardStreamingTests(unittest.TestCase):
    def candidate(self, operation="admin", fingerprint="8" * 64):
        peers = ["1" * 64, fingerprint]
        return server_snapshot(peers=peers)

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

    def test_unknown_removal_emits_sanitized_stopped(self):
        baseline = server_snapshot()
        removed = server_snapshot(peers=["9" * 64])
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

    def test_client_observation_samples_coordinated_traffic_inside_window(self):
        before, after = self.client_states()
        state = copy.deepcopy(before)

        class CoordinatedClock(FakeClock):
            def sleep(self, seconds):
                state.update(copy.deepcopy(after))
                super().sleep(seconds)

        receipt = guard.run_client_observe(
            client_request(before, after),
            lambda _request: copy.deepcopy(state),
            CoordinatedClock(),
        )
        self.assertEqual(receipt["before_counter_sha256"], sha(before["counter_state"]))
        self.assertEqual(receipt["after_counter_sha256"], sha(after["counter_state"]))

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
        request = {
            "schema": "home-gateway/p3-peer-guard-request/v2",
            "mode": "emergency-rollback",
            "payload_sha256": PAYLOAD,
            "protocol_sha256": sha(EXPECTED_PROTOCOL),
            "manifest_sha256": "b" * 64,
            "install_receipt_sha256": "c" * 64,
            "nonce": "d" * 64,
            "candidate_receipt_sha256": "8" * 64,
            "candidate_fingerprint_sha256": "f" * 64,
            "pre_peer_fingerprint_sha256": ["1" * 64],
            "post_peer_fingerprint_sha256": ["1" * 64, "f" * 64],
            "baseline_peer_set_sha256": sha(["1" * 64]),
            "persistent_config_path": "/opt/amnezia/awg/awg0.conf",
            "metadata_path": "/opt/amnezia/awg/clientsTable",
            "temporary_path": "/tmp/p3-candidate-dddddddddddddddddddddddddddddddd.tmp",
            "syncconf_path": "/opt/amnezia/awg/awg0.conf",
            "prepared_syncconf_sha256": "9" * 64,
            "pre_persistent_config_sha256": "2" * 64,
            "pre_live_peer_set_sha256": sha(["1" * 64, "f" * 64]),
            "pre_metadata_sha256": "3" * 64,
            "pre_temporary_state_sha256": "4" * 64,
            "pre_runtime_identity_sha256": "5" * 64,
            "baseline_persistent_config_sha256": "6" * 64,
            "baseline_metadata_sha256": "7" * 64,
            "baseline_temporary_state_sha256": sha(b"ABSENT"),
            "baseline_runtime_identity_sha256": "a" * 64,
            "baseline_ipv6_policy_sha256": "b" * 64,
        }
        identity = {key: request[key] for key in guard.ROLLBACK_PLAN_KEYS}
        request["rollback_plan_sha256"] = sha(identity)
        request["confirmation"] = (
            "P3-EMERGENCY-ROLLBACK-" + request["rollback_plan_sha256"][:16].upper()
        )
        return request

    def adapter_action(self, adapter):
        request = self.rollback_request()
        request["candidate_fingerprint_sha256"] = adapter.candidate
        request["pre_peer_fingerprint_sha256"] = []
        request["post_peer_fingerprint_sha256"] = [adapter.candidate]
        request["baseline_peer_set_sha256"] = sha([])
        request["pre_live_peer_set_sha256"] = sha([adapter.candidate])
        request["rollback_plan_sha256"] = sha(
            {key: request[key] for key in guard.ROLLBACK_PLAN_KEYS}
        )
        request["confirmation"] = (
            "P3-EMERGENCY-ROLLBACK-" + request["rollback_plan_sha256"][:16].upper()
        )
        return request

    def test_container_adapter_reopens_durable_state_after_process_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            first = FakeContainerRollbackFilesystem(pathlib.Path(directory))
            action = self.adapter_action(first)
            token = first({"action": "begin", **action})["recovery_state"]
            restarted = FakeContainerRollbackFilesystem(pathlib.Path(directory))
            recovered = restarted(
                {"action": "recover", **action, "recovery_state": token}
            )
            self.assertEqual(
                recovered,
                {
                    "recovered": True,
                    "recovery_syncconf_path": guard.CONTAINER_CONFIG_PATH,
                },
            )
            self.assertEqual(restarted.config, first.config)
            self.assertEqual(restarted.clients, first.clients)
            self.assertEqual(restarted.temporary, first.temporary)

    def test_container_adapter_recovers_after_interrupted_second_write_and_staging(
        self,
    ):
        with tempfile.TemporaryDirectory() as directory:
            first = FakeContainerRollbackFilesystem(
                pathlib.Path(directory), fail_write_number=2
            )
            action = self.adapter_action(first)
            token = first({"action": "begin", **action})["recovery_state"]
            with self.assertRaisesRegex(RuntimeError, "interrupted"):
                first({"action": "remove", **action, "recovery_state": token})
            restarted = FakeContainerRollbackFilesystem(pathlib.Path(directory))
            restarted({"action": "recover", **action, "recovery_state": token})
            writes = [event for event in restarted.events if isinstance(event, tuple)]
            self.assertEqual(
                [event[0] for event in writes[:3]], ["run", "write", "write"]
            )
            self.assertEqual(
                writes[1][2:][0], guard.container_staging_paths(action["nonce"])[0]
            )
            self.assertEqual(
                writes[2][2:][0], guard.container_staging_paths(action["nonce"])[1]
            )

    def test_container_adapter_recovers_after_interrupted_temporary_stage(self):
        with tempfile.TemporaryDirectory() as directory:
            first = FakeContainerRollbackFilesystem(
                pathlib.Path(directory), fail_temporary=True
            )
            action = self.adapter_action(first)
            token = first({"action": "begin", **action})["recovery_state"]
            with self.assertRaisesRegex(RuntimeError, "temporary"):
                first({"action": "recover", **action, "recovery_state": token})
            restarted = FakeContainerRollbackFilesystem(pathlib.Path(directory))
            restarted({"action": "recover", **action, "recovery_state": token})
            self.assertEqual(restarted.temporary, first.temporary)
            self.assertEqual(restarted.events[0][0], "run")

    def test_recovery_discovery_rejects_every_orphan_artifact_without_manifest(self):
        token = "e" * 64
        for name in ("config", "clients", "temporary", "new_config", "new_clients"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                adapter = FakeContainerRollbackFilesystem(pathlib.Path(directory))
                action = self.adapter_action(adapter)
                orphan = adapter._recovery_paths(token)[name]
                orphan.write_bytes(b"orphan")
                restarted = FakeContainerRollbackFilesystem(pathlib.Path(directory))
                with self.assertRaisesRegex(RuntimeError, "ROLLBACK_UNPROVEN"):
                    restarted({"action": "resume", **action})
                self.assertTrue(orphan.exists())

    def test_cleanup_interruption_at_each_artifact_remains_discoverable_and_unproven(
        self,
    ):
        for failure_number in range(1, 6):
            with (
                self.subTest(failure_number=failure_number),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = pathlib.Path(directory)
                adapter = CleanupCrashContainerRollbackFilesystem(root, failure_number)
                action = self.adapter_action(adapter)
                token = adapter({"action": "begin", **action})["recovery_state"]
                with self.assertRaisesRegex(OSError, "cleanup interruption"):
                    adapter(
                        {
                            "action": "cleanup",
                            **action,
                            "recovery_state": token,
                        }
                    )
                remaining = list(root.glob(".p3-recovery-*"))
                self.assertTrue(remaining)
                restarted = FakeContainerRollbackFilesystem(root)
                with self.assertRaisesRegex(RuntimeError, "ROLLBACK_UNPROVEN"):
                    restarted({"action": "resume", **action})
                self.assertTrue(any(path.exists() for path in remaining))

    def test_syncconf_reopens_durable_state_and_refuses_a_swapped_container(self):
        with tempfile.TemporaryDirectory() as directory:
            adapter = FakeContainerRollbackFilesystem(pathlib.Path(directory))
            action = self.adapter_action(adapter)
            token = adapter({"action": "begin", **action})["recovery_state"]
            adapter({"action": "remove", **action, "recovery_state": token})
            events_before_sync = list(adapter.events)
            with (
                mock.patch.object(
                    adapter,
                    "_resolve_container",
                    return_value="replacement-container-id",
                ),
                self.assertRaisesRegex(ValueError, "container identity changed"),
            ):
                adapter.syncconf(pathlib.Path(action["syncconf_path"]), token)
            self.assertEqual(adapter.events, events_before_sync)

    def test_temporary_recovery_is_staged_and_atomically_renamed(self):
        calls = []

        def stream_runner(arguments, data, timeout_seconds, maximum_bytes):
            calls.append((arguments, data))
            return guard.CommandResult(0, b"", b"")

        adapter = guard.ContainerRollbackFilesystem(stream_runner=stream_runner)
        target = "/tmp/p3-candidate-" + ("d" * 32) + ".tmp"
        stage = "/tmp/.p3-recover-" + ("d" * 32) + ".tmp"
        adapter._write_temporary("synthetic-container-id", target, stage, b"temp")
        self.assertEqual(len(calls), 1)
        arguments = calls[0][0]
        self.assertIn(stage, arguments)
        self.assertIn(target, arguments)
        self.assertIn("mv -T", arguments[-5])

    def test_rollback_observation_reuses_canonical_server_snapshot_hashes(self):
        adapter = guard.ContainerRollbackFilesystem()
        action = self.rollback_request()
        snapshot = server_snapshot(
            container_identity_sha256=sha(b"synthetic-container-id"),
            persistent_config_sha256="1" * 64,
            metadata_sha256="2" * 64,
            temporary_state_sha256="3" * 64,
            runtime_identity_sha256="4" * 64,
            live_peer_set_sha256=sha(action["post_peer_fingerprint_sha256"]),
            peer_fingerprint_sha256=action["post_peer_fingerprint_sha256"],
        )
        with (
            mock.patch.object(
                adapter, "_resolve_container", return_value="synthetic-container-id"
            ),
            mock.patch.object(adapter, "_run", return_value=b"canonical-syncconf"),
            mock.patch.object(
                guard, "collect_server_snapshot", return_value=snapshot
            ) as collector,
        ):
            observed = adapter._observation(action)
        self.assertEqual(
            observed["persistent_config_sha256"], snapshot["persistent_config_sha256"]
        )
        self.assertEqual(observed["metadata_sha256"], snapshot["metadata_sha256"])
        self.assertEqual(
            observed["temporary_state_sha256"], snapshot["temporary_state_sha256"]
        )
        self.assertEqual(
            observed["runtime_identity_sha256"], snapshot["runtime_identity_sha256"]
        )
        self.assertEqual(
            collector.call_args.args[0]["expected_ipv6_policy_sha256"],
            action["baseline_ipv6_policy_sha256"],
        )

    def test_interrupted_process_is_recovered_and_requires_new_approval(self):
        calls = []

        def filesystem(action):
            calls.append(action["action"])
            if action["action"] == "resume":
                return {"recovery_state": "d" * 64}
            if action["action"] == "recover":
                return {
                    "recovered": True,
                    "recovery_syncconf_path": action["syncconf_path"],
                }
            if action["action"] == "verify-recovery":
                return guard.rollback_expected_observation(action, phase="pre")
            if action["action"] == "cleanup":
                return {"cleaned": True}
            raise AssertionError(action)

        syncs = []
        with self.assertRaisesRegex(RuntimeError, "RECOVERED_INTERRUPTED"):
            guard.run_emergency_rollback(
                self.rollback_request(),
                filesystem,
                lambda path, recovery_state: syncs.append(str(path)),
            )
        self.assertEqual(calls, ["resume", "recover", "verify-recovery", "cleanup"])
        self.assertEqual(syncs, [str(pathlib.Path(guard.CONTAINER_CONFIG_PATH))])

    def test_resumed_recovery_failures_are_unproven_and_never_start_fresh_mutation(
        self,
    ):
        for failure in ("recover", "sync", "verify", "cleanup"):
            calls = []

            def filesystem(action, *, failure=failure, calls=calls):
                calls.append(action["action"])
                if action["action"] == "resume":
                    return {"recovery_state": "d" * 64}
                if action["action"] == "recover":
                    if failure == "recover":
                        raise RuntimeError("synthetic recover detail")
                    return {
                        "recovered": True,
                        "recovery_syncconf_path": action["syncconf_path"],
                    }
                if action["action"] == "verify-recovery":
                    observed = guard.rollback_expected_observation(action, phase="pre")
                    if failure == "verify":
                        observed["runtime_identity_sha256"] = "0" * 64
                    return observed
                if action["action"] == "cleanup":
                    return {"cleaned": failure != "cleanup"}
                raise AssertionError(action)

            def syncconf(path, recovery_state, *, failure=failure):
                if failure == "sync":
                    raise RuntimeError("synthetic sync detail")

            with (
                self.subTest(failure=failure),
                self.assertRaisesRegex(RuntimeError, "ROLLBACK_UNPROVEN"),
            ):
                guard.run_emergency_rollback(
                    self.rollback_request(), filesystem, syncconf
                )
            self.assertNotIn("inspect", calls)

    def test_malformed_durable_manifest_is_unproven_and_retained(self):
        with tempfile.TemporaryDirectory() as directory:
            first = FakeContainerRollbackFilesystem(pathlib.Path(directory))
            action = self.adapter_action(first)
            token = first({"action": "begin", **action})["recovery_state"]
            manifest = first._recovery_paths(token)["manifest"]
            manifest.write_bytes(b"{")
            restarted = FakeContainerRollbackFilesystem(pathlib.Path(directory))
            with self.assertRaisesRegex(RuntimeError, "ROLLBACK_UNPROVEN"):
                guard.run_emergency_rollback(
                    action, restarted, lambda path, recovery_state: None
                )
            self.assertTrue(manifest.exists())

    def test_container_rollback_staging_and_writer_are_nonce_bound(self):
        config_stage, clients_stage = guard.container_staging_paths("d" * 64)
        self.assertEqual(
            config_stage,
            "/opt/amnezia/awg/.p3-next-dddddddddddddddddddddddddddddddd.conf",
        )
        self.assertEqual(
            clients_stage,
            "/opt/amnezia/awg/.p3-next-dddddddddddddddddddddddddddddddd.clients",
        )
        arguments = guard.container_writer_arguments(
            "container-id",
            "/opt/amnezia/awg/awg0.conf",
            config_stage,
            123,
        )
        self.assertEqual(
            arguments[:4], ["/usr/bin/docker", "exec", "-i", "container-id"]
        )
        self.assertEqual(
            arguments[-4:],
            ["p3-writer", "/opt/amnezia/awg/awg0.conf", config_stage, "123"],
        )
        self.assertNotIn("d" * 64, " ".join(arguments))
        with self.assertRaisesRegex(ValueError, "nonce"):
            guard.container_staging_paths("not-a-nonce")

    def test_emergency_rollback_rejects_every_legacy_or_noncanonical_target(self):
        for name, value in (
            ("persistent_config_path", "/opt/amnezia/awg/wg0.conf"),
            ("metadata_path", "/opt/amnezia/awg/peers.json"),
            ("temporary_path", "/run/home-gateway-p3-peer-guard/candidate.tmp"),
            ("syncconf_path", "/run/home-gateway-p3-peer-guard/awg.conf"),
        ):
            request = self.rollback_request()
            request[name] = value
            identity = {key: request[key] for key in guard.ROLLBACK_PLAN_KEYS}
            request["rollback_plan_sha256"] = sha(identity)
            request["confirmation"] = (
                "P3-EMERGENCY-ROLLBACK-" + request["rollback_plan_sha256"][:16].upper()
            )
            with (
                self.subTest(name=name),
                self.assertRaisesRegex(ValueError, "emergency rollback"),
            ):
                guard.validate_request("emergency-rollback", request)

    def test_emergency_rollback_is_exact_candidate_bound_and_one_syncconf(self):
        calls = []

        def filesystem(action):
            calls.append((action["action"], action.get("candidate_fingerprint_sha256")))
            if action["action"] == "resume":
                return {"recovery_state": ""}
            if action["action"] == "inspect":
                return guard.rollback_expected_observation(action, phase="pre")
            if action["action"] == "begin":
                return {"recovery_state": "opaque-test-token"}
            if action["action"] == "remove":
                self.assertEqual(action["recovery_state"], "opaque-test-token")
                return {"removed": True}
            if action["action"] == "verify":
                return guard.rollback_expected_observation(action, phase="baseline")
            if action["action"] == "cleanup":
                return {"cleaned": True}
            raise AssertionError(action)

        receipt = guard.run_emergency_rollback(
            self.rollback_request(),
            filesystem,
            lambda path, recovery_state: calls.append(("syncconf", str(path))),
        )
        self.assertTrue(receipt["restored"])
        self.assertEqual(
            [name for name, _ in calls],
            ["resume", "inspect", "begin", "remove", "syncconf", "verify", "cleanup"],
        )

    def test_emergency_rollback_revalidates_before_any_mutation(self):
        calls = []
        with self.assertRaisesRegex(ValueError, "pre observation"):
            guard.run_emergency_rollback(
                self.rollback_request(),
                lambda action: (
                    calls.append(action)
                    or (
                        {"recovery_state": ""}
                        if action["action"] == "resume"
                        else {
                            **guard.rollback_expected_observation(action, phase="pre"),
                            "candidate_fingerprint_sha256": "0" * 64,
                        }
                    )
                ),
                lambda path, recovery_state: calls.append(path),
            )
        self.assertEqual([item["action"] for item in calls], ["resume", "inspect"])

    def test_emergency_rollback_recomputes_plan_and_rejects_every_bound_mutation(self):
        original = self.rollback_request()
        for field in sorted(guard.ROLLBACK_PLAN_KEYS):
            mutated = copy.deepcopy(original)
            value = mutated[field]
            if isinstance(value, list):
                mutated[field] = value + ["0" * 64]
            elif isinstance(value, str) and len(value) == 64:
                mutated[field] = "0" * 64
            else:
                mutated[field] = str(value) + ".drift"
            with self.subTest(field=field), self.assertRaises(ValueError):
                guard.validate_request("emergency-rollback", mutated)

    def test_emergency_rollback_recovers_pre_state_when_syncconf_fails(self):
        calls = []

        def filesystem(action):
            calls.append(action["action"])
            if action["action"] == "resume":
                return {"recovery_state": ""}
            if action["action"] == "inspect":
                return guard.rollback_expected_observation(action, phase="pre")
            if action["action"] == "begin":
                return {"recovery_state": "opaque-test-token"}
            if action["action"] == "remove":
                return {"removed": True}
            if action["action"] == "recover":
                self.assertEqual(action["recovery_state"], "opaque-test-token")
                return {
                    "recovered": True,
                    "recovery_syncconf_path": action["syncconf_path"],
                }
            if action["action"] == "verify-recovery":
                return guard.rollback_expected_observation(action, phase="pre")
            if action["action"] == "cleanup":
                return {"cleaned": True}
            raise AssertionError(action)

        sync_calls = []

        def syncconf(path, recovery_state):
            sync_calls.append(str(path))
            if len(sync_calls) == 1:
                raise RuntimeError("synthetic sync failure")

        with self.assertRaisesRegex(RuntimeError, "rollback failed atomically"):
            guard.run_emergency_rollback(self.rollback_request(), filesystem, syncconf)
        self.assertEqual(
            calls,
            [
                "resume",
                "inspect",
                "begin",
                "remove",
                "recover",
                "verify-recovery",
                "cleanup",
            ],
        )
        self.assertEqual(len(sync_calls), 2)

    def test_recovery_sync_failure_is_unproven_and_preserves_cleanup_material(self):
        calls = []

        def filesystem(action):
            calls.append(action["action"])
            if action["action"] == "resume":
                return {"recovery_state": ""}
            if action["action"] == "inspect":
                return guard.rollback_expected_observation(action, phase="pre")
            if action["action"] == "begin":
                return {"recovery_state": "durable-token"}
            if action["action"] == "remove":
                return {"removed": True}
            if action["action"] == "recover":
                return {
                    "recovered": True,
                    "recovery_syncconf_path": action["syncconf_path"],
                }
            raise AssertionError(action)

        with self.assertRaisesRegex(RuntimeError, "ROLLBACK_UNPROVEN"):
            guard.run_emergency_rollback(
                self.rollback_request(),
                filesystem,
                lambda path, recovery_state: (_ for _ in ()).throw(
                    RuntimeError("sync")
                ),
            )
        self.assertNotIn("cleanup", calls)

    def test_emergency_rollback_recovers_when_the_first_mutation_fails(self):
        calls = []

        def filesystem(action):
            calls.append(action["action"])
            if action["action"] == "resume":
                return {"recovery_state": ""}
            if action["action"] == "inspect":
                return guard.rollback_expected_observation(action, phase="pre")
            if action["action"] == "begin":
                return {"recovery_state": "durable-token"}
            if action["action"] == "remove":
                raise RuntimeError("first mutation failed")
            if action["action"] == "recover":
                return {
                    "recovered": True,
                    "recovery_syncconf_path": action["syncconf_path"],
                }
            if action["action"] == "verify-recovery":
                return guard.rollback_expected_observation(action, phase="pre")
            if action["action"] == "cleanup":
                return {"cleaned": True}
            raise AssertionError(action)

        with self.assertRaisesRegex(RuntimeError, "failed atomically"):
            guard.run_emergency_rollback(
                self.rollback_request(), filesystem, lambda path, recovery_state: None
            )
        self.assertEqual(
            calls,
            [
                "resume",
                "inspect",
                "begin",
                "remove",
                "recover",
                "verify-recovery",
                "cleanup",
            ],
        )

    def test_emergency_rollback_preserves_recovery_material_when_recovery_is_unproved(
        self,
    ):
        calls = []

        def filesystem(action):
            calls.append(action["action"])
            if action["action"] == "resume":
                return {"recovery_state": ""}
            if action["action"] == "inspect":
                return guard.rollback_expected_observation(action, phase="pre")
            if action["action"] == "begin":
                return {"recovery_state": "durable-token"}
            if action["action"] == "remove":
                raise RuntimeError("mutation")
            if action["action"] == "recover":
                raise RuntimeError("recovery")
            raise AssertionError(action)

        with self.assertRaisesRegex(RuntimeError, "ROLLBACK_UNPROVEN"):
            guard.run_emergency_rollback(
                self.rollback_request(), filesystem, lambda path, recovery_state: None
            )
        self.assertNotIn("cleanup", calls)

    def test_default_command_runner_caps_a_real_noisy_child_and_reaps_it(self):
        command = [
            sys.executable,
            "-c",
            "import sys;sys.stdout.buffer.write(b'x'*1048576);sys.stdout.flush()",
        ]
        result = guard._run_bounded_process(command, None, 5, 4096)
        self.assertTrue(result.overflowed)
        self.assertLessEqual(len(result.stdout), 4097)
        self.assertEqual(result.stderr, b"")

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
