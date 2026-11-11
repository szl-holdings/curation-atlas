"""Deterministic Python-made receipts for the TypeScript cross-check (lib/receipt-crosscheck.test.ts).

    python3 tests/receipts/generate_py.py          write py-fixture.json
    python3 tests/receipts/generate_py.py --check  exit 1 if it is stale

Every value is synthetic and comes from a seeded PRNG (mulberry32, so the output
does not depend on the Python version's ``random`` module).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))

from comparison import POLICY_DEFINITIONS  # noqa: E402
from receipt import UNDEFINED, create_receipt, receipt_json  # noqa: E402

PY_FIXTURE = Path(__file__).resolve().parent / "py-fixture.json"
SEED = 20261111
ORG = "atlas-synth"
REPO_NAMES = (".github", "alpha", "beta", "gamma", "delta")
BLOBS = ("1" * 40, "2" * 40, "ab" * 20)


class Mulberry32:
    def __init__(self, seed: int):
        self.state = seed & 0xFFFFFFFF

    def __call__(self) -> float:
        self.state = (self.state + 0x6D2B79F5) & 0xFFFFFFFF
        t = self.state
        t = ((t ^ (t >> 15)) * (t | 1)) & 0xFFFFFFFF
        t ^= (t + (((t ^ (t >> 7)) * (t | 61)) & 0xFFFFFFFF)) & 0xFFFFFFFF
        return ((t ^ (t >> 14)) & 0xFFFFFFFF) / 4294967296

    def int(self, n: int) -> int:
        return int(self() * n)

    def pick(self, items):
        return items[self.int(len(items))]


FINITE = (0, -0.0, 1e21, 1e-7, 5e-324, 2**53 + 1, 2**64, 10**30, -(2**63), 0.1 + 0.2, 1.7976931348623157e308,
          57.49999999999999, 10**400, 4.35, 100.0)
NON_FINITE = (float("nan"), float("inf"), float("-inf"))
TEXTS = ("", "plain", "caf\u00e9", "e\u0301", "\ud800", "\udfff", "x\ud83d", "\ud83d\ude00", "\U0001F600", "\u2028\u2029",
         "\x00\x1f\x7f", 'quote " backslash \\', "\ufeffbom", "\uff61", "__proto__", "line\nbreak\ttab")
KEYS = ("a", "A", "b", "10", "2", "01", "", "__proto__", "\uff61", "\U0001F600", "\ud83d\ude00x", "\ud800", "\u00e9",
        "e\u0301")


def mixed_case(rng: Mulberry32, value: str) -> str:
    if rng() < 0.25:
        return "".join(c.upper() if rng() < 0.5 else c for c in value)
    return value


def policy(rng: Mulberry32, definition: dict) -> dict:
    r = rng()
    if definition.get("setPrefix"):
        if r < 0.4:
            return {"key": definition["key"], "state": "ABSENT", "path": None, "blobSha": None, "sourceRepo": None,
                    "memberCount": 0}
        if r < 0.85:
            members = [f".github/workflows/ci.yml:{rng.pick(BLOBS)}"]
            return {"key": definition["key"], "state": "LOCAL", "path": ".github/workflows/*",
                    "blobSha": "set:" + "|".join(members), "sourceRepo": None, "memberCount": len(members)}
        return {"key": definition["key"], "state": "UNKNOWN", "path": None, "blobSha": None, "sourceRepo": None}
    if r < 0.45:
        return {"key": definition["key"], "state": "ABSENT", "path": None, "blobSha": None, "sourceRepo": None}
    if r < 0.85:
        return {"key": definition["key"], "state": "LOCAL", "path": rng.pick(definition["candidates"]),
                "blobSha": rng.pick(BLOBS), "sourceRepo": None}
    return {"key": definition["key"], "state": "UNKNOWN", "path": None, "blobSha": None, "sourceRepo": None}


def timestamp(rng: Mulberry32) -> str:
    fraction = rng.pick(("", "", ".%03d" % rng.int(1000), ".5"))
    zone = rng.pick(("Z", "Z", "+01:00", "-07:00"))
    return "2026-%02d-%02dT%02d:%02d:%02d%s%s" % (
        1 + rng.int(12), 1 + rng.int(28), rng.int(24), rng.int(60), rng.int(60), fraction, zone)


def generated_at(rng: Mulberry32) -> str:
    return "2026-11-%02dT%02d:%02d:%02d.%03dZ" % (
        1 + rng.int(30), rng.int(24), rng.int(60), rng.int(60), rng.int(1000))


def audit(rng: Mulberry32, *, js_safe_only: bool) -> dict:
    size = rng.pick((0, 0, 0, 0, 0, 0, 1, 2))
    names = list(REPO_NAMES)
    for i in range(len(names) - 1, 0, -1):
        j = rng.int(i + 1)
        names[i], names[j] = names[j], names[i]
    repositories = []
    for name in names[:size]:
        policies = [policy(rng, definition) for definition in POLICY_DEFINITIONS]
        for i in range(len(policies) - 1, 0, -1):
            j = rng.int(i + 1)
            policies[i], policies[j] = policies[j], policies[i]
        repositories.append({
            "fullName": mixed_case(rng, f"{ORG}/{name}"),
            "headSha": rng.pick(("a" * 40, "B" * 40, "abc123", None)),
            "treeSha": rng.pick(("c" * 40, None)),
            "treeComplete": rng() < 0.8,
            "policies": policies,
        })
    numbers = FINITE if js_safe_only else FINITE + NON_FINITE
    value: dict = {
        "schemaVersion": 1,
        "mode": rng.pick(("MEASURED", "MEASURED", "SAMPLE", "BLOCKED", "UNAVAILABLE")),
        "publicOnly": True,
        "org": {"login": mixed_case(rng, ORG), "name": rng.pick(TEXTS)},
        "observedAt": timestamp(rng),
        "repositories": repositories,
        "scores": {"alignment": None, "consistency": rng.pick(numbers), "evidenceCoverage": rng.pick(numbers)},
        "limitations": [rng.pick(TEXTS) for _ in range(rng.int(3))],
        "extra": {rng.pick(KEYS): rng.pick(numbers) if rng() < 0.5 else rng.pick(TEXTS) for _ in range(rng.int(4))},
        "tupleAsArray": tuple(rng.pick(numbers) for _ in range(rng.int(3))),
    }
    if not js_safe_only and rng() < 0.5:
        value["dropped"] = UNDEFINED  # a JavaScript undefined: omitted from the canonical form
    return value


def build_py_fixture() -> dict:
    rng = Mulberry32(SEED)
    receipts = []
    for i in range(200):
        # Odd receipts go through json.dumps (ensure_ascii, no NaN); even ones through receipt_json.
        via_dumps = i % 2 == 1
        receipt = create_receipt(audit(rng, js_safe_only=via_dumps), generated_at(rng))
        if via_dumps:
            text = json.dumps(receipt, ensure_ascii=True, allow_nan=False, indent=2 if i < 10 else None)
        else:
            text = receipt_json(receipt)
        receipts.append({"id": f"py-receipt-{i}", "generatedAt": receipt["generatedAt"],
                         "receiptSha256": receipt["receiptSha256"], "serializer": "json.dumps" if via_dumps else "receipt_json",
                         "text": text})
    return {"schema": "curation-atlas/receipt-vectors/1", "generator": "tests/receipts/generate_py.py", "seed": SEED,
            "receipts": receipts}


def fixture_text(fixture: dict) -> str:
    lines = []
    for key, value in fixture.items():
        head = "  " + json.dumps(key) + ": "
        if isinstance(value, list):
            items = ",\n".join("    " + json.dumps(item, ensure_ascii=False, separators=(",", ":")) for item in value)
            lines.append(head + "[\n" + items + "\n  ]")
        else:
            lines.append(head + json.dumps(value, ensure_ascii=False, separators=(",", ":")))
    return "{\n" + ",\n".join(lines) + "\n}\n"


def main(argv: list[str]) -> int:
    text = fixture_text(build_py_fixture())
    if "--check" in argv:
        current = PY_FIXTURE.read_text(encoding="utf-8") if PY_FIXTURE.exists() else ""
        if current != text:
            print(f"{PY_FIXTURE} is stale: run python3 tests/receipts/generate_py.py", file=sys.stderr)
            return 1
        print(f"{PY_FIXTURE} is current")
        return 0
    PY_FIXTURE.write_text(text, encoding="utf-8", newline="\n")
    print(f"wrote {PY_FIXTURE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
