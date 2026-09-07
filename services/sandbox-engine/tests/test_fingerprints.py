import hashlib
import unittest

from failroom_sandbox.fingerprints import configuration_digest


class FingerprintTests(unittest.TestCase):
    def test_matches_explicit_canonical_representation(self):
        canonical = b'{"cpu":1,"network":"none"}'
        expected = "sha256:" + hashlib.sha256(canonical).hexdigest()
        self.assertEqual(configuration_digest({"network": "none", "cpu": 1}), expected)

    def test_key_order_does_not_change_fingerprint(self):
        self.assertEqual(
            configuration_digest({"limits": {"cpu": 1, "pids": 32}, "ro": True}),
            configuration_digest({"ro": True, "limits": {"pids": 32, "cpu": 1}}),
        )

    def test_value_type_list_order_and_nested_changes_invalidate(self):
        configurations = (
            {"value": 1},
            {"value": 1.0},
            {"value": True},
            {"value": "1"},
            {"value": [1, 2]},
            {"value": [2, 1]},
            {"value": {"cpu": 1}},
            {"value": {"cpu": 2}},
        )
        hashes = {configuration_digest(c) for c in configurations}
        self.assertEqual(len(hashes), len(configurations))

    def test_input_mutation_changes_next_fingerprint(self):
        value = {"limits": [32, 64]}
        original = configuration_digest(value)
        self.assertEqual(value, {"limits": [32, 64]})
        value["limits"][0] = 128
        self.assertNotEqual(original, configuration_digest(value))

    def test_non_json_documents_are_rejected_without_echo(self):
        for value in (
            None,
            [],
            "secret-token",
            {1: "secret-token"},
            {"x": {False: "secret-token"}},
            {"x": (1, 2)},
            {"x": {1, 2}},
            {"x": object()},
            {"x": float("nan")},
            {"x": float("inf")},
            {"x": float("-inf")},
        ):
            with self.subTest(value_type=type(value)):
                with self.assertRaises(ValueError) as caught:
                    configuration_digest(value)
                self.assertEqual(str(caught.exception), "INVALID_CONFIGURATION")

    def test_cycle_is_rejected(self):
        cyclic = {}
        cyclic["self"] = cyclic
        with self.assertRaisesRegex(ValueError, "^INVALID_CONFIGURATION$"):
            configuration_digest(cyclic)

    def test_unicode_null_and_shared_values_are_supported(self):
        shared = [None, "한글"]
        value = {"first": shared, "second": shared}
        self.assertEqual(
            configuration_digest(value),
            configuration_digest({"second": [None, "한글"], "first": [None, "한글"]}),
        )


if __name__ == "__main__":
    unittest.main()
