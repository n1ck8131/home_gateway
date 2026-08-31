import importlib.util
import io
import json
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "p3-prelive-server-observer.py"
SPEC = importlib.util.spec_from_file_location("p3_pre_live_server_observer", SCRIPT)
observer = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = observer
SPEC.loader.exec_module(observer)


class PreliveServerObserverTests(unittest.TestCase):
    def test_attested_frame_rejects_truncation_extension_hash_and_replay(self):
        payload = b"synthetic read-only observer"
        nonce = "1" * 64
        protocol = "3" * 64
        ipv6 = "4" * 64
        frame = observer.encode_attested_frame(payload, nonce, protocol, ipv6)
        self.assertEqual(
            observer.read_attested_frame(io.BytesIO(frame), nonce, protocol, ipv6),
            payload,
        )
        for changed, message in (
            (frame[:-1], "length"),
            (frame + b"x", "trailing"),
            (frame.replace(payload, b"synthetic read-only observeq"), "hash"),
        ):
            with (
                self.subTest(message=message),
                self.assertRaisesRegex(ValueError, message),
            ):
                observer.read_attested_frame(
                    io.BytesIO(changed), nonce, protocol, ipv6
                )
        with self.assertRaisesRegex(ValueError, "nonce"):
            observer.read_attested_frame(
                io.BytesIO(frame), "2" * 64, protocol, ipv6
            )
        with self.assertRaisesRegex(ValueError, "protocol"):
            observer.read_attested_frame(
                io.BytesIO(frame), nonce, "5" * 64, ipv6
            )

    def test_observation_accepts_only_exact_sanitized_27_field_baseline(self):
        baseline = json.loads(
            (ROOT / "tests" / "fixtures" / "p3" / "server-baseline-v2.json").read_text()
        )
        receipt = observer.build_observation_receipt(
            baseline,
            payload_sha256="9" * 64,
            protocol_sha256="b" * 64,
            nonce="2" * 64,
        )
        self.assertEqual(
            receipt["server_baseline_sha256"],
            "68943c7693ed9a442b206749572dc44e2e44a595af080e254836f29ff73ebb1f",
        )
        encoded = json.dumps(receipt, sort_keys=True)
        self.assertNotIn("PublicKey", encoded)
        self.assertNotIn("192.0.2.", encoded)
        for mutation in (dict(baseline), dict(baseline)):
            if len(mutation) == 27:
                mutation.pop("runtime_identity_sha256")
            with self.assertRaises(ValueError):
                observer.build_observation_receipt(
                    mutation,
                    payload_sha256="9" * 64,
                    protocol_sha256="b" * 64,
                    nonce="2" * 64,
                )

    def test_read_only_command_contract_has_no_remote_write_verb(self):
        commands = observer.read_only_command_contract("container-id")
        self.assertIn(
            [
                "/usr/bin/docker",
                "exec",
                "container-id",
                "cat",
                "/opt/amnezia/awg/clientsTable",
            ],
            commands,
        )
        flattened = " ".join(part for command in commands for part in command)
        for forbidden in (" rm ", " mv ", " cp ", "tee", "syncconf", "scp"):
            self.assertNotIn(forbidden, " " + flattened + " ")
        self.assertFalse(any(command[0] == "/usr/bin/awg" for command in commands))


if __name__ == "__main__":
    unittest.main()
