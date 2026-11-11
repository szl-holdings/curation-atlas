"""Receipt canonical form: Python port vs TypeScript-made vectors (stdlib unittest).

Fails closed: a missing or short vector file is a failure, never a skip.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from comparison import ReceiptError, verify_imported_receipt  # noqa: E402
from receipt import (  # noqa: E402
    RECEIPT_CLAIM,
    RECEIPT_SCHEMA,
    UNDEFINED,
    canonicalize,
    create_receipt,
    iso_now_ms,
    js_length,
    js_number,
    js_string,
    receipt_digest,
    receipt_json,
)

RECEIPTS_DIR = Path(__file__).resolve().parents[2] / "tests" / "receipts"
MIN_CANONICAL_VECTORS = 500
RECEIPT_COUNT = 200


def load_fixture(name: str) -> dict:
    path = RECEIPTS_DIR / name
    if not path.is_file():
        raise AssertionError(f"missing vector file {path}; run the generators in tests/receipts/")
    return json.loads(path.read_text(encoding="utf-8"))


def load_generator():
    spec = importlib.util.spec_from_file_location("curation_atlas_generate_py", RECEIPTS_DIR / "generate_py.py")
    if spec is None or spec.loader is None:
        raise AssertionError("tests/receipts/generate_py.py is missing")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class NumberAndStringFormTests(unittest.TestCase):
    def test_numbers_print_like_ecmascript(self):
        cases = {
            0: "0", -0.0: "0", 1: "1", -1.5: "-1.5", 100.0: "100", 1e20: "100000000000000000000",
            1e21: "1e+21", -1e21: "-1e+21", 1.5e300: "1.5e+300", 1e-6: "0.000001", 1e-7: "1e-7",
            1.2345e-7: "1.2345e-7", 123e-20: "1.23e-18", 5e-324: "5e-324", 0.1 + 0.2: "0.30000000000000004",
            2**53 + 1: "9007199254740992", 2**64: "18446744073709552000", 1.7976931348623157e308: "1.7976931348623157e+308",
            57.49999999999999: "57.49999999999999", 0.000123: "0.000123",
        }
        for value, expected in cases.items():
            with self.subTest(value=value):
                self.assertEqual(canonicalize(value), expected)
        self.assertEqual(canonicalize(-0.0), "0")
        self.assertEqual(canonicalize([-0.0, 0.0, -0]), "[0,0,0]")

    def test_non_finite_and_overflowing_values_print_null(self):
        for value in (float("nan"), float("inf"), float("-inf"), 10**400, -(10**400)):
            with self.subTest(value=value):
                self.assertEqual(canonicalize(value), "null")
        with self.assertRaises(ValueError):
            js_number(float("nan"))

    def test_strings_escape_like_json_stringify(self):
        cases = {
            "plain": '"plain"', 'q"b\\': '"q\\"b\\\\"', "\b\t\n\f\r": '"\\b\\t\\n\\f\\r"',
            "\x00\x1f": '"\\u0000\\u001f"', "\x7f\u2028\u2029": '"\x7f\u2028\u2029"', "\ud800": '"\\ud800"',
            "\udfff": '"\\udfff"', "x\ud83d": '"x\\ud83d"', "\ud83d\ude00": '"\U0001F600"', "\U0001F600": '"\U0001F600"',
            "\ude00\ud83d": '"\\ude00\\ud83d"', "/": '"/"', "\u00e9": '"\u00e9"',
        }
        for value, expected in cases.items():
            with self.subTest(value=value):
                self.assertEqual(js_string(value), expected)

    def test_keys_sort_by_utf16_code_units(self):
        value = {"\uff61": 1, "\U0001F600": 2, "b": 3, "B": 4, "10": 5, "2": 6, "": 7}
        self.assertEqual(canonicalize(value), '{"":7,"10":5,"2":6,"B":4,"b":3,"\U0001F600":2,"\uff61":1}')
        self.assertEqual(js_length("\U0001F600"), 2)

    def test_undefined_callables_and_tuples(self):
        self.assertEqual(canonicalize({"a": UNDEFINED, "b": 1}), '{"b":1}')
        self.assertEqual(canonicalize([UNDEFINED, len]), "[null,null]")
        self.assertEqual(canonicalize({"f": len}), '{"f":null}')
        self.assertEqual(canonicalize(UNDEFINED), "null")
        self.assertEqual(canonicalize((1, "x", None, True, False)), '[1,"x",null,true,false]')

    def test_unsupported_values_are_refused(self):
        for value in ({1, 2}, {1: "x"}, b"bytes", {"\ud83d\ude00": 1, "\U0001F600": 2}):
            with self.subTest(value=value), self.assertRaises(TypeError):
                canonicalize(value)


class CanonicalVectorTests(unittest.TestCase):
    def test_typescript_canonical_vectors_match_byte_for_byte(self):
        vectors = load_fixture("ts-fixture.json")["canonicalVectors"]
        self.assertGreaterEqual(len(vectors), MIN_CANONICAL_VECTORS)
        mismatches = [v["id"] for v in vectors if canonicalize(json.loads(v["input"])) != v["canonical"]]
        self.assertEqual(mismatches, [], f"{len(mismatches)} of {len(vectors)} canonical vectors differ")
        classes = {v["cls"] for v in vectors}
        self.assertEqual(classes, {"number", "string", "key", "nested"})


class ReceiptTests(unittest.TestCase):
    def test_create_receipt_envelope_and_digest(self):
        receipt = create_receipt({"b": 1, "a": [1.0, "\ud800"]}, "2026-10-07T12:00:00.000Z")
        self.assertEqual(list(receipt), ["receiptSchema", "generatedAt", "claim", "audit", "receiptSha256"])
        self.assertEqual(receipt["receiptSchema"], RECEIPT_SCHEMA)
        self.assertEqual(receipt["claim"], RECEIPT_CLAIM)
        payload = {key: value for key, value in receipt.items() if key != "receiptSha256"}
        canonical = canonicalize(payload)
        self.assertIn('"audit":{"a":[1,"\\ud800"],"b":1}', canonical)
        self.assertEqual(receipt["receiptSha256"], hashlib.sha256(canonical.encode("utf-8")).hexdigest())
        self.assertEqual(receipt["receiptSha256"], receipt_digest(canonical))

    def test_generated_at_must_be_a_to_iso_string_timestamp(self):
        for bad in ("2026-10-07T12:00:00Z", "2026-10-07T12:00:00.000+00:00", "2026-10-07 12:00:00.000Z", 1, ""):
            with self.subTest(bad=bad), self.assertRaises(ReceiptError) as caught:
                create_receipt({}, bad)
            self.assertEqual(caught.exception.code, "invalid_generated_at")
        self.assertRegex(create_receipt({})["generatedAt"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")
        self.assertRegex(iso_now_ms(), r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")

    def test_receipt_json_is_valid_json_with_the_same_canonical_form(self):
        receipt = create_receipt({"n": [float("nan"), -0.0, 2**53 + 1], "s": "\ud800"}, "2026-10-07T12:00:00.000Z")
        text = receipt_json(receipt)
        parsed = json.loads(text)
        self.assertEqual(canonicalize(parsed), canonicalize(receipt))
        self.assertNotIn("NaN", text)

    def test_typescript_receipts_verify_in_python_200_of_200(self):
        receipts = load_fixture("ts-fixture.json")["receipts"]
        self.assertEqual(len(receipts), RECEIPT_COUNT)
        verified = recreated = 0
        for item in receipts:
            with self.subTest(receipt=item["id"]):
                result = verify_imported_receipt(item["text"])
                self.assertEqual(result["receiptSha256"], item["receiptSha256"])
                verified += 1
                envelope = json.loads(item["text"])
                again = create_receipt(envelope["audit"], item["generatedAt"])
                self.assertEqual(again["receiptSha256"], item["receiptSha256"])
                recreated += 1
        self.assertEqual((verified, recreated), (RECEIPT_COUNT, RECEIPT_COUNT))

    def test_tampering_with_any_field_breaks_the_digest(self):
        item = load_fixture("ts-fixture.json")["receipts"][10]
        envelope = json.loads(item["text"])
        for mutate in (
            lambda e: e["audit"].__setitem__("mode", "BLOCKED" if e["audit"]["mode"] != "BLOCKED" else "SAMPLE"),
            lambda e: e.__setitem__("generatedAt", "2020-01-01T00:00:00.000Z"),
            lambda e: e["audit"]["org"].__setitem__("login", e["audit"]["org"]["login"] + "x"),
        ):
            changed = json.loads(item["text"])
            mutate(changed)
            with self.assertRaises(ReceiptError) as caught:
                verify_imported_receipt(json.dumps(changed))
            self.assertEqual(caught.exception.code, "digest_mismatch")
        self.assertEqual(verify_imported_receipt(json.dumps(envelope))["receiptSha256"], item["receiptSha256"])

    def test_python_fixture_is_current(self):
        generator = load_generator()
        expected = generator.fixture_text(generator.build_py_fixture())
        path = RECEIPTS_DIR / "py-fixture.json"
        self.assertTrue(path.is_file(), "missing tests/receipts/py-fixture.json")
        self.assertEqual(path.read_text(encoding="utf-8"), expected,
                         "py-fixture.json is stale: run python3 tests/receipts/generate_py.py")
        receipts = json.loads(expected)["receipts"]
        self.assertEqual(len(receipts), RECEIPT_COUNT)
        for item in receipts:
            self.assertEqual(verify_imported_receipt(item["text"])["receiptSha256"], item["receiptSha256"])


if __name__ == "__main__":
    unittest.main()
