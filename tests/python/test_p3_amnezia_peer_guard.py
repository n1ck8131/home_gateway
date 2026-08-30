import importlib.util
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "p3-amnezia-peer-guard.py"
SPEC = importlib.util.spec_from_file_location("p3_amnezia_peer_guard", SCRIPT)
guard = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(guard)


def snapshot(*, peer="baseline", persistent="p", live="l", metadata="m", temporary="t"):
    return {
        "persistent_hash": persistent,
        "live_hash": live,
        "metadata_hash": metadata,
        "temporary_hash": temporary,
        "peers": [peer],
        "runtime": {
            "iptables": [
                {"rule": "allow", "created_at": "one", "packets": 1, "bytes": 2}
            ],
            "nft": [{"rule": "allow", "counter_packets": 3, "counter_bytes": 4}],
            "bindings": [
                {
                    "protocol": "udp",
                    "address_hash": "x",
                    "port": 1,
                    "recv_q": 2,
                    "send_q": 3,
                }
            ],
        },
    }


class PeerGuardTests(unittest.TestCase):
    def test_semantic_normalization_ignores_only_reviewed_runtime_drift(self):
        first = snapshot()
        second = snapshot()
        second["runtime"]["iptables"][0].update(created_at="two", packets=99, bytes=100)
        second["runtime"]["nft"][0].update(counter_packets=99, counter_bytes=100)
        second["runtime"]["bindings"][0].update(recv_q=99, send_q=100)
        self.assertEqual(guard.semantic_hash(first), guard.semantic_hash(second))
        second["runtime"]["iptables"][0]["rule"] = "changed"
        self.assertNotEqual(guard.semantic_hash(first), guard.semantic_hash(second))

    def test_partial_candidate_convergence_waits_without_validation_or_rollback(self):
        baseline = snapshot()
        partial = snapshot(peer="candidate", persistent="p2")
        decision = guard.classify_candidate(baseline, partial, expected_delta=1)
        self.assertEqual(decision.label, "WAIT_CONVERGENCE")
        self.assertFalse(decision.validate)
        self.assertFalse(decision.rollback)

    def test_primary_and_rollback_exceptions_keep_separate_sanitized_labels(self):
        result = guard.sanitize_failure(
            RuntimeError("raw primary"), RuntimeError("raw rollback")
        )
        self.assertEqual(
            result,
            {
                "primary_error": "PRIMARY_EXCEPTION",
                "rollback_error": "ROLLBACK_EXCEPTION",
            },
        )
        self.assertNotIn("raw", str(result))

    def test_eof_or_invalid_control_token_never_mutates(self):
        calls = []
        for token in ("", "ARM", "invalid"):
            result = guard.handle_control_token(token, lambda: calls.append("mutated"))
            self.assertEqual(result["transport_error"], "CONTROL_TOKEN_INVALID_OR_EOF")
        self.assertEqual(calls, [])

    def test_stable_convergence_requires_two_exact_samples_five_seconds_apart(self):
        values = [
            snapshot(
                peer="candidate",
                persistent="p2",
                live="l2",
                metadata="m2",
                temporary="t2",
            )
        ] * 2
        sleeps = []
        stable = guard.await_stable(
            lambda: values.pop(0),
            sleep=lambda seconds: sleeps.append(seconds),
            timeout_seconds=180,
        )
        self.assertEqual(stable["peers"], ["candidate"])
        self.assertIn(5, sleeps)

    def test_stable_convergence_never_sleeps_or_samples_past_monotonic_deadline(self):
        clock = [1000.0]
        sleeps = []
        observations = []

        def sleep(seconds):
            sleeps.append(seconds)
            clock[0] += seconds

        def observe():
            observations.append(clock[0])
            return snapshot(peer=f"candidate-{len(observations)}")

        with self.assertRaisesRegex(TimeoutError, "timed out"):
            guard.await_stable(
                observe,
                sleep=sleep,
                monotonic=lambda: clock[0],
                timeout_seconds=6,
            )

        self.assertLessEqual(clock[0], 1006.0)
        self.assertTrue(all(value <= 1006.0 for value in observations))
        self.assertEqual(sleeps, [2])

    def test_emergency_rollback_is_exact_one_peer_and_one_syncconf(self):
        baseline = snapshot()
        baseline["peers"] = ["baseline"]
        candidate = snapshot(
            peer="baseline", persistent="p2", live="l2", metadata="m2", temporary="t2"
        )
        candidate["peers"] = ["baseline", "candidate"]
        calls = []
        result = guard.execute_emergency_rollback(
            baseline,
            candidate,
            candidate,
            baseline,
            remove_exact=lambda identity: calls.append(("remove", identity)),
            syncconf=lambda: calls.append(("syncconf", None)),
        )
        self.assertTrue(result["restored"])
        self.assertEqual([name for name, _ in calls], ["remove", "syncconf"])

    def test_changed_candidate_blocks_emergency_rollback(self):
        baseline = snapshot()
        baseline["peers"] = ["baseline"]
        candidate = snapshot(
            peer="candidate", persistent="p2", live="l2", metadata="m2", temporary="t2"
        )
        candidate["peers"] = ["baseline", "candidate"]
        changed = dict(candidate)
        changed["metadata_hash"] = "changed"
        calls = []
        with self.assertRaisesRegex(ValueError, "identity"):
            guard.execute_emergency_rollback(
                baseline,
                candidate,
                changed,
                baseline,
                remove_exact=lambda identity: calls.append(identity),
                syncconf=lambda: calls.append("sync"),
            )
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
