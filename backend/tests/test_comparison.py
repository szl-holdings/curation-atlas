"""Receipt import and audit comparison: Python port vs lib/comparison.ts (stdlib unittest).

Fails closed: a missing or short vector file is a failure, never a skip. Every
place the port is stricter than the TypeScript is decision P15-D5 and is pinned
by a fixture entry that the TypeScript accepts (lib/receipt-crosscheck.test.ts).
"""

from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from comparison import (  # noqa: E402
    FAIL_CLOSED_DIVERGENCES,
    MAX_RECEIPT_BYTES,
    POLICY_DEFINITIONS,
    ReceiptError,
    compare_audits,
    parse_timestamp,
    project_comparison_audit,
    verify_imported_receipt,
)
from receipt import canonicalize, create_receipt, receipt_json  # noqa: E402

RECEIPTS_DIR = Path(__file__).resolve().parents[2] / "tests" / "receipts"
MIN_COMPARISON_VECTORS = 300
CODES = {"ADDED": "A", "REMOVED": "R", "UNCHANGED": "U", "UNKNOWN": "K"}
TS_ERRORS = {
    "Run an audit for the same organization as the loaded receipt.": "different_org",
    "The loaded receipt is newer than the displayed audit. Run a fresh scan before comparing.": "newer_baseline",
}


def ts_fixture() -> dict:
    path = RECEIPTS_DIR / "ts-fixture.json"
    if not path.is_file():
        raise AssertionError(f"missing vector file {path}; run node --experimental-strip-types tests/receipts/generate.mts")
    return json.loads(path.read_text(encoding="utf-8"))


def change_code(delta: dict) -> str:
    if delta["change"] in CODES:
        return CODES[delta["change"]]
    return "C" if delta["reason"] == "The observed content or workflow-set fingerprint differs." else "L"


def absent(key: str) -> dict:
    return {"key": key, "state": "ABSENT", "path": None, "blobSha": None, "sourceRepo": None}


def fixture() -> dict:
    """A complete, pinned MEASURED audit of three synthetic repositories."""
    repositories = []
    for name in (".github", "alpha", "beta"):
        policies = [absent(definition["key"]) for definition in POLICY_DEFINITIONS]
        license_policy = next(policy for policy in policies if policy["key"] == "license")
        license_policy.update(state="LOCAL", path="LICENSE", blobSha="e" * 40)
        repositories.append({"name": name, "fullName": f"szl-holdings/{name}", "headSha": "a" * 40,
                             "treeSha": "b" * 40, "treeComplete": True, "policies": policies})
    return {"schemaVersion": 1, "mode": "MEASURED", "publicOnly": True, "org": {"login": "szl-holdings"},
            "observedAt": "2026-10-07T12:00:00Z", "repositories": repositories}


def find(audit: dict, index: int, key: str) -> dict:
    return next(policy for policy in audit["repositories"][index]["policies"] if policy["key"] == key)


def delta(result: dict, full_name: str, key: str) -> dict:
    return next(item for item in result["deltas"] if item["fullName"] == full_name and item["key"] == key)


def seal(audit: dict, generated_at: str = "2026-10-08T09:30:00.000Z") -> str:
    return receipt_json(create_receipt(audit, generated_at))


class PortedTypeScriptTests(unittest.TestCase):
    """The seven tests in lib/comparison.test.ts, ported."""

    def test_receipt_import_verifies_the_full_envelope_and_rejects_tampering(self):
        receipt = create_receipt(fixture(), "2026-10-08T09:30:00.000Z")
        self.assertEqual(verify_imported_receipt(json.dumps(receipt))["audit"]["orgLogin"], "szl-holdings")
        receipt["audit"]["org"]["name"] = "tampered"
        with self.assertRaises(ReceiptError) as caught:
            verify_imported_receipt(json.dumps(receipt))
        self.assertEqual(caught.exception.code, "digest_mismatch")

    def test_addition_incomplete_source_and_cohort_departure(self):
        before = fixture()
        after = copy.deepcopy(before)
        after["observedAt"] = "2026-10-07T13:00:00Z"
        find(after, 0, "security").update(state="LOCAL", path="SECURITY.md", blobSha="c" * 40)
        after["repositories"][1]["treeComplete"] = False
        left = after["repositories"].pop()
        result = compare_audits(project_comparison_audit(before), after)
        self.assertEqual(delta(result, after["repositories"][0]["fullName"], "security")["change"], "ADDED")
        self.assertEqual(delta(result, after["repositories"][1]["fullName"], "security")["change"], "UNKNOWN")
        self.assertEqual(result["leftCohort"], [left["fullName"]])
        self.assertEqual(result["enteredCohort"], [])
        self.assertEqual(result["overlapCount"], 2)

    def test_sample_and_short_head_inputs_never_establish_transitions(self):
        before = fixture()
        after = copy.deepcopy(before)
        before["mode"] = "SAMPLE"
        self.assertTrue(all(d["change"] == "UNKNOWN" for d in compare_audits(project_comparison_audit(before), after)["deltas"]))
        before["mode"] = "MEASURED"
        before["repositories"][0]["headSha"] = "a" * 12
        result = compare_audits(project_comparison_audit(before), after)
        name = before["repositories"][0]["fullName"]
        self.assertTrue(all(d["change"] == "UNKNOWN" for d in result["deltas"] if d["fullName"] == name))
        self.assertTrue(any(d["change"] == "UNCHANGED" for d in result["deltas"] if d["fullName"] != name))

    def test_different_organization_newer_baseline_and_duplicate_identities(self):
        before = fixture()
        newer = copy.deepcopy(before)
        newer["observedAt"] = "2026-10-08T12:00:00Z"
        with self.assertRaises(ReceiptError) as caught:
            compare_audits(project_comparison_audit(newer), before)
        self.assertEqual(caught.exception.code, "newer_baseline")
        projected = project_comparison_audit(before)
        projected["orgLogin"] = "different"
        with self.assertRaises(ReceiptError) as caught:
            compare_audits(projected, before)
        self.assertEqual(caught.exception.code, "different_org")
        before["repositories"].append(before["repositories"][0])
        with self.assertRaises(ReceiptError) as caught:
            project_comparison_audit(before)
        self.assertEqual(caught.exception.code, "repeated_repository")

    def test_workflow_count_equality_cannot_hide_changed_fingerprints(self):
        before = fixture()
        after = copy.deepcopy(before)
        find(before, 0, "workflows").update(state="LOCAL", path=".github/workflows/*",
                                            blobSha="set:.github/workflows/ci.yml:" + "c" * 40, memberCount=1)
        find(after, 0, "workflows").update(state="LOCAL", path=".github/workflows/*",
                                           blobSha="set:.github/workflows/ci.yml:" + "d" * 40, memberCount=1)
        result = compare_audits(project_comparison_audit(before), after)
        self.assertEqual(delta(result, before["repositories"][0]["fullName"], "workflows")["change"], "CHANGED")
        self.assertEqual(delta(result, before["repositories"][0]["fullName"], "workflows")["reason"],
                         "The observed content or workflow-set fingerprint differs.")

    def test_unsupported_inheritance_and_malformed_sets_cannot_establish_transitions(self):
        before = fixture()
        after = copy.deepcopy(before)
        find(before, 1, "workflows").update(state="LOCAL", path=".github/workflows/*", blobSha="set:garbage", memberCount=1)
        find(before, 1, "codeowners").update(state="INHERITED", path=".github/CODEOWNERS", blobSha="c" * 40,
                                             sourceRepo="szl-holdings/.github")
        result = compare_audits(project_comparison_audit(before), after)
        self.assertEqual(delta(result, before["repositories"][1]["fullName"], "workflows")["change"], "UNKNOWN")
        self.assertEqual(delta(result, before["repositories"][1]["fullName"], "codeowners")["change"], "UNKNOWN")

    def test_optional_absent_counts_do_not_create_drift(self):
        before = fixture()
        after = copy.deepcopy(before)
        old = find(before, 0, "workflows")
        old.update(state="ABSENT", path=None, blobSha=None, sourceRepo=None, memberCount=0)
        find(after, 0, "workflows").pop("memberCount", None)
        name = before["repositories"][0]["fullName"]
        self.assertEqual(delta(compare_audits(project_comparison_audit(before), after), name, "workflows")["change"], "UNCHANGED")
        old["memberCount"] = 1
        self.assertEqual(delta(compare_audits(project_comparison_audit(before), after), name, "workflows")["change"], "UNKNOWN")


class ComparisonEdgeTests(unittest.TestCase):
    def test_inherited_policy_needs_a_pinned_local_origin_in_the_org_github_repo(self):
        before = fixture()
        find(before, 0, "security").update(state="LOCAL", path=".github/SECURITY.md", blobSha="1" * 40)
        find(before, 1, "security").update(state="INHERITED", path=".github/SECURITY.md", blobSha="1" * 40,
                                           sourceRepo="szl-holdings/.github")
        after = copy.deepcopy(before)
        after["observedAt"] = "2026-10-07T13:00:00Z"
        self.assertEqual(delta(compare_audits(project_comparison_audit(before), after), "szl-holdings/alpha", "security")["change"], "UNCHANGED")
        for change in (
            lambda a: find(a, 1, "security").update(sourceRepo="szl-holdings/beta"),
            lambda a: find(a, 0, "security").update(blobSha="2" * 40),
            lambda a: a["repositories"][0].update(treeComplete=False),
            lambda a: find(a, 1, "codeowners").update(state="INHERITED", path=".github/CODEOWNERS", blobSha="1" * 40,
                                                      sourceRepo="szl-holdings/.github"),
        ):
            changed = copy.deepcopy(after)
            change(changed)
            result = compare_audits(project_comparison_audit(before), changed)
            key = "codeowners" if find(changed, 1, "codeowners")["state"] == "INHERITED" else "security"
            self.assertEqual(delta(result, "szl-holdings/alpha", key)["change"], "UNKNOWN")

    def test_location_change_with_same_fingerprint_and_removal(self):
        before = fixture()
        after = copy.deepcopy(before)
        after["observedAt"] = "2026-10-07T13:00:00Z"
        find(before, 1, "security").update(state="LOCAL", path="SECURITY.md", blobSha="1" * 40)
        find(after, 1, "security").update(state="LOCAL", path=".github/SECURITY.md", blobSha="1" * 40)
        find(after, 2, "license").update(state="ABSENT", path=None, blobSha=None)
        after["repositories"][2]["headSha"] = "f" * 40
        result = compare_audits(project_comparison_audit(before), after)
        moved = delta(result, "szl-holdings/alpha", "security")
        self.assertEqual((moved["change"], moved["reason"]),
                         ("CHANGED", "The policy location or inheritance changed while the observed fingerprint matches."))
        self.assertEqual(delta(result, "szl-holdings/beta", "license")["change"], "REMOVED")
        self.assertEqual(result["changedRevisionCount"], 1)

    def test_workflow_sets_with_repeated_or_non_yaml_members_are_unknown(self):
        for blob, count in (("set:.github/workflows/a.yml:" + "1" * 40 + "|.github/workflows/a.yml:" + "2" * 40, 2),
                            ("set:.github/workflows/a.txt:" + "1" * 40, 1),
                            ("set:.github/workflows/a.YAML:" + "1" * 40, 2)):
            before = fixture()
            find(before, 0, "workflows").update(state="LOCAL", path=".github/workflows/*", blobSha=blob, memberCount=count)
            result = compare_audits(project_comparison_audit(before), copy.deepcopy(before))
            self.assertEqual(delta(result, "szl-holdings/.github", "workflows")["change"], "UNKNOWN", blob)
        before = fixture()
        find(before, 0, "workflows").update(state="LOCAL", path=".github/workflows/*",
                                            blobSha="set:.github/workflows/a.YAML:" + "1" * 40, memberCount=1)
        self.assertEqual(delta(compare_audits(project_comparison_audit(before), copy.deepcopy(before)),
                               "szl-holdings/.github", "workflows")["change"], "UNCHANGED")

    def test_inheritance_only_from_the_org_github_repository(self):
        before = fixture()
        find(before, 1, "security").update(state="LOCAL", path=".github/SECURITY.md", blobSha="1" * 40)
        find(before, 2, "security").update(state="INHERITED", path=".github/SECURITY.md", blobSha="1" * 40,
                                           sourceRepo="szl-holdings/alpha")
        result = compare_audits(project_comparison_audit(before), copy.deepcopy(before))
        self.assertEqual(delta(result, "szl-holdings/alpha", "security")["change"], "UNCHANGED")
        self.assertEqual(delta(result, "szl-holdings/beta", "security")["change"], "UNKNOWN")

    def test_uppercase_hex_fingerprints_are_comparable_like_the_typescript(self):
        before = fixture()
        find(before, 0, "license").update(blobSha="E" * 40)
        find(before, 0, "workflows").update(state="LOCAL", path=".github/workflows/*",
                                            blobSha="set:.github/workflows/ci.yml:" + "AB" * 20, memberCount=1)
        result = compare_audits(project_comparison_audit(before), copy.deepcopy(before))
        self.assertEqual(delta(result, "szl-holdings/.github", "license")["change"], "UNCHANGED")
        self.assertEqual(delta(result, "szl-holdings/.github", "workflows")["change"], "UNCHANGED")

    def test_absent_policies_with_leftover_evidence_are_unknown(self):
        for leftover in ({"path": "LICENSE"}, {"blobSha": "1" * 40}, {"sourceRepo": "szl-holdings/.github"}):
            before = fixture()
            find(before, 1, "governance").update(leftover)
            result = compare_audits(project_comparison_audit(before), copy.deepcopy(before))
            self.assertEqual(delta(result, "szl-holdings/alpha", "governance")["change"], "UNKNOWN", leftover)
            self.assertEqual(delta(result, "szl-holdings/beta", "governance")["change"], "UNCHANGED")

    def test_baseline_must_be_a_projection(self):
        for bad in (None, [], {"mode": ["MEASURED"], "orgLogin": "x", "observedAt": "2026-10-07T12:00:00Z", "repositories": []},
                    {"mode": "MEASURED", "orgLogin": "x", "observedAt": "2026-10-07T12:00:00", "repositories": []}):
            with self.subTest(bad=bad), self.assertRaises(ReceiptError):
                compare_audits(bad, fixture())

    def test_typescript_comparison_vectors_match(self):
        data = ts_fixture()
        pool, vectors = data["comparisonPool"], data["comparisonVectors"]
        self.assertGreaterEqual(len(vectors), MIN_COMPARISON_VECTORS)
        seen_codes: set[str] = set()
        seen_errors: set[str] = set()
        for vector in vectors:
            with self.subTest(vector=vector["id"]):
                previous = project_comparison_audit(pool[vector["previous"]])
                if "error" in vector:
                    with self.assertRaises(ReceiptError) as caught:
                        compare_audits(previous, pool[vector["current"]])
                    self.assertEqual(caught.exception.code, TS_ERRORS[vector["error"]])
                    self.assertEqual(str(caught.exception), vector["error"])
                    seen_errors.add(caught.exception.code)
                    continue
                result = compare_audits(previous, pool[vector["current"]])
                changes = "".join(change_code(item) for item in result["deltas"])
                self.assertEqual(
                    (result["overlapCount"], result["changedRevisionCount"], result["enteredCohort"], result["leftCohort"], changes),
                    (vector["overlapCount"], vector["changedRevisionCount"], vector["enteredCohort"], vector["leftCohort"], vector["changes"]),
                )
                seen_codes.update(changes)
        self.assertEqual(seen_codes, {"A", "R", "U", "C", "L", "K"}, "vectors no longer cover every change kind")
        self.assertEqual(seen_errors, {"different_org", "newer_baseline"})

    def test_policy_definitions_match_typescript_and_the_python_scanner(self):
        ts = [{key: definition.get(key) for key in ("key", "label", "inheritable", "candidates", "setPrefix")}
              for definition in ts_fixture()["policyDefinitions"]]
        mine = [{"key": d["key"], "label": d["label"], "inheritable": d["inheritable"],
                 "candidates": list(d["candidates"]), "setPrefix": d.get("setPrefix")} for d in POLICY_DEFINITIONS]
        self.assertEqual(mine, ts)
        import audit  # noqa: PLC0415  (needs httpx, a backend dependency)

        scanner = [{"key": d["key"], "label": d["label"], "inheritable": d["inheritable"],
                    "candidates": list(d["candidates"]), "setPrefix": d.get("setPrefix")} for d in audit.POLICIES]
        self.assertEqual(mine, scanner)


class VerifyGuardTests(unittest.TestCase):
    """Refusals the TypeScript verifier shares (same inputs, same outcome)."""

    def assertCode(self, code: str, source) -> None:
        with self.assertRaises(ReceiptError) as caught:
            verify_imported_receipt(source)
        self.assertEqual(caught.exception.code, code)

    def test_envelope_guards(self):
        good = json.loads(seal(fixture()))
        self.assertEqual(verify_imported_receipt(json.dumps(good))["audit"]["orgLogin"], "szl-holdings")
        upper = dict(good, receiptSha256=good["receiptSha256"].upper())
        self.assertEqual(verify_imported_receipt(json.dumps(upper))["receiptSha256"], good["receiptSha256"])
        self.assertCode("invalid_schema", json.dumps(dict(good, receiptSchema="curation-atlas/2")))
        self.assertCode("invalid_digest", json.dumps(dict(good, receiptSha256="z" * 64)))
        self.assertCode("invalid_digest", json.dumps(dict(good, receiptSha256="a" * 63)))
        self.assertCode("invalid_text", json.dumps(dict(good, receiptSha256="a" * 65)))
        self.assertCode("invalid_digest", json.dumps(dict(good, receiptSha256="\u0661" * 64)))
        self.assertCode("invalid_object", "[]")
        self.assertCode("invalid_json", "{")
        self.assertCode("invalid_json", '{"a": NaN}')
        self.assertCode("invalid_json", '{"a": Infinity}')
        self.assertCode("invalid_encoding", b'{"a": "\xff"}')
        self.assertCode("invalid_json", 12)

    def test_size_limit_counts_utf8_bytes_like_text_encoder(self):
        def sized(total: int, filler: str = "x") -> str:
            head, tail = '{"a":"', '"}'
            return head + filler * (total - len(head) - len(tail)) + tail
        self.assertCode("invalid_schema", sized(MAX_RECEIPT_BYTES))
        self.assertCode("too_large", sized(MAX_RECEIPT_BYTES + 1))
        self.assertCode("too_large", sized(MAX_RECEIPT_BYTES - 8) + "\u20ac" * 3)
        self.assertCode("too_large", sized(MAX_RECEIPT_BYTES - 2) + "\ud800")
        self.assertCode("invalid_json", sized(MAX_RECEIPT_BYTES - 4) + "\U0001F600")

    def test_nesting_limit_is_48_levels_below_the_envelope(self):
        def nested(levels: int) -> str:
            return '{"receiptSchema":"x","n":' + "[" * levels + "0" + "]" * levels + "}"
        self.assertCode("invalid_schema", nested(47))
        self.assertCode("too_deep", nested(48))

    def test_audit_guards(self):
        cases = [
            ("unsupported_audit", lambda a: a.update(schemaVersion=2)),
            ("unsupported_audit", lambda a: a.update(schemaVersion=True)),
            ("unsupported_audit", lambda a: a.update(publicOnly=1)),
            ("invalid_mode", lambda a: a.update(mode="measured")),
            ("invalid_object", lambda a: a.update(org=None)),
            ("invalid_text", lambda a: a["org"].update(login="x" * 40)),
            ("invalid_org", lambda a: a["org"].update(login="-bad")),
            ("invalid_repositories", lambda a: a.update(repositories={})),
            ("invalid_repository", lambda a: a["repositories"][0].update(fullName="other/alpha")),
            ("invalid_repository", lambda a: a["repositories"][0].update(fullName="szl-holdings/al pha")),
            ("missing_tree_coverage", lambda a: a["repositories"][0].update(treeComplete=1)),
            ("incomplete_policies", lambda a: a["repositories"][0]["policies"].pop()),
            ("invalid_policy_key", lambda a: a["repositories"][0]["policies"][0].update(key="nope")),
            ("invalid_policy_key", lambda a: a["repositories"][0]["policies"][1].update(key=a["repositories"][0]["policies"][0]["key"])),
            ("invalid_state", lambda a: a["repositories"][0]["policies"][0].update(state="local")),
            ("invalid_member_count", lambda a: a["repositories"][0]["policies"][0].update(memberCount=-1)),
            ("invalid_member_count", lambda a: a["repositories"][0]["policies"][0].update(memberCount=1.5)),
            ("invalid_member_count", lambda a: a["repositories"][0]["policies"][0].update(memberCount=True)),
            ("invalid_member_count", lambda a: a["repositories"][0]["policies"][0].update(memberCount=None)),
            ("invalid_text", lambda a: a["repositories"][0]["policies"][0].pop("path")),
            ("invalid_text", lambda a: a["repositories"][0].update(headSha="a" * 41)),
            ("invalid_text", lambda a: a["repositories"][0].update(error=None)),
            ("invalid_timestamp", lambda a: a.update(observedAt="yesterday")),
            ("invalid_timestamp", lambda a: a.update(observedAt="2026-10-07T12:00:00.000+00:00" + " " * 12)),
        ]
        for code, change in cases:
            audit = fixture()
            change(audit)
            with self.subTest(code=code), self.assertRaises(ReceiptError) as caught:
                project_comparison_audit(audit)
            self.assertEqual(caught.exception.code, code)

    def test_projection_keeps_typescript_shapes(self):
        audit = fixture()
        audit["org"]["login"] = "SZL-Holdings"
        audit["repositories"][0].update(fullName="SZL-Holdings/.GitHub", headSha="A" * 40, error="rate limited")
        find(audit, 0, "workflows").update(memberCount=0)
        find(audit, 0, "license").update(memberCount=3, sourceRepo=None)
        projected = project_comparison_audit(audit)
        self.assertEqual(projected["orgLogin"], "szl-holdings")
        repository = projected["repositories"][0]
        self.assertEqual(list(repository), ["fullName", "headSha", "treeSha", "treeComplete", "error", "policies"])
        self.assertEqual((repository["fullName"], repository["headSha"]), ("szl-holdings/.github", "a" * 40))
        workflows = next(p for p in repository["policies"] if p["key"] == "workflows")
        license_policy = next(p for p in repository["policies"] if p["key"] == "license")
        self.assertEqual(workflows["memberCount"], 0)
        self.assertNotIn("memberCount", license_policy)
        self.assertEqual(canonicalize(projected["observedAt"]), '"2026-10-07T12:00:00Z"')

    def test_timestamps_parse_strictly_and_truncate_like_date_parse(self):
        self.assertEqual(parse_timestamp("2026-10-07T12:00:00.1Z"), parse_timestamp("2026-10-07T12:00:00.100Z"))
        self.assertEqual(parse_timestamp("2026-10-07T14:00:00+02:00"), parse_timestamp("2026-10-07T12:00:00Z"))
        self.assertEqual(parse_timestamp("2026-10-07T06:30:00-05:30"), parse_timestamp("2026-10-07T12:00:00Z"))
        self.assertEqual(parse_timestamp("2024-02-29T00:00:00Z").day, 29)
        for bad in ("2026-10-07T12:00:00+24:00", "2026-10-07T12:00:00+05:60", "2026-10-07T12:60:00Z",
                    "2026-10-07T12:00:60Z", "2026-00-07T12:00:00Z", "9999-12-31T23:59:59-01:00", "\u0662026-10-07T12:00:00Z"):
            with self.subTest(bad=bad), self.assertRaises(ReceiptError):
                parse_timestamp(bad)


class FailClosedDivergenceTests(unittest.TestCase):
    """P15-D5: inputs the TypeScript verifier accepts and this port refuses."""

    def test_registry_matches_the_fixture(self):
        fixture_ids = [item["id"] for item in ts_fixture()["divergences"]]
        self.assertEqual(sorted(fixture_ids), sorted(item["id"] for item in FAIL_CLOSED_DIVERGENCES))
        self.assertTrue(all(item["decision"] == "P15-D5" for item in ts_fixture()["divergences"]))

    def test_each_receipt_divergence_is_refused_with_its_own_guard(self):
        refused = []
        for item in ts_fixture()["divergences"]:
            if item["kind"] != "receipt":
                continue
            with self.subTest(divergence=item["id"]), self.assertRaises(ReceiptError) as caught:
                verify_imported_receipt(item["text"])
            self.assertEqual(caught.exception.code, item["pythonCode"], item["id"])
            refused.append(item["id"])
        self.assertEqual(len(refused), 16)

    def test_empty_error_string_never_counts_as_pinned(self):
        item = next(entry for entry in ts_fixture()["divergences"] if entry["id"] == "D5-empty-error")
        result = compare_audits(project_comparison_audit(item["previous"]), item["current"])
        name = item["previous"]["repositories"][0]["fullName"].lower()
        changes = "".join(change_code(d) for d in result["deltas"] if d["fullName"] == name)
        self.assertEqual(changes, "K" * len(POLICY_DEFINITIONS))
        self.assertNotEqual(item["tsChanges"], changes, "the TypeScript side no longer diverges; update P15-D5")


if __name__ == "__main__":
    unittest.main()
