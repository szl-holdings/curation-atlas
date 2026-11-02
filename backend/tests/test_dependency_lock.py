from __future__ import annotations

import re
import unittest
from pathlib import Path


BACKEND = Path(__file__).resolve().parents[1]
REQUIREMENT = re.compile(r"^([a-z0-9][a-z0-9._-]*)==([^\s;\\]+)", re.IGNORECASE)
HASH = re.compile(r"--hash=sha256:[0-9a-f]{64}$")


def pinned_rows(path: Path) -> dict[str, str]:
    rows: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        match = REQUIREMENT.match(line)
        if match:
            name, version = match.groups()
            rows[name.lower().replace("_", "-")] = version
    return rows


class DependencyLockTests(unittest.TestCase):
    def test_lock_contains_direct_pins_and_hashes_every_distribution(self):
        direct = pinned_rows(BACKEND / "requirements.txt")
        locked = pinned_rows(BACKEND / "requirements.lock")
        self.assertEqual(
            {name: locked.get(name) for name in direct},
            direct,
            "regenerate requirements.lock when a direct pin changes",
        )

        stanzas = re.split(
            r"(?m)(?=^[a-z0-9][a-z0-9._-]*==)",
            (BACKEND / "requirements.lock").read_text(encoding="utf-8"),
        )[1:]
        self.assertEqual(len(stanzas), len(locked))
        for stanza in stanzas:
            package = REQUIREMENT.match(stanza)
            self.assertIsNotNone(package)
            hashes = [line.strip().rstrip(" \\") for line in stanza.splitlines() if "--hash=" in line]
            self.assertTrue(hashes, f"{package.group(1)} has no artifact hashes")
            self.assertTrue(all(HASH.fullmatch(value) for value in hashes))

    def test_lock_records_declared_floor_and_time_cutoff(self):
        header = (BACKEND / "requirements.lock").read_text(encoding="utf-8")[:500]
        self.assertIn("--python-version 3.12", header)
        self.assertIn("--universal", header)
        self.assertIn("--generate-hashes", header)
        self.assertIn("--exclude-newer 2026-11-02T00:00:00Z", header)


if __name__ == "__main__":
    unittest.main()
