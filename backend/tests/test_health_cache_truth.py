"""GET /healthz must never make a source binding look cached or certified."""
from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from app import app


class HealthCacheTruthTests(unittest.TestCase):
    def test_health_is_no_store_and_non_attesting(self):
        with TestClient(app) as client:
            response = client.get("/healthz")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers.get("cache-control"), "no-store")
        self.assertEqual(response.headers.get("x-content-type-options"), "nosniff")
        self.assertEqual(response.json()["upstreamReadiness"], "UNKNOWN")
        self.assertEqual(response.json()["status"], "PROCESS_ALIVE")

    def test_source_revision_change_remains_fresh_but_only_declared(self):
        with TestClient(app) as client:
            with patch.dict(os.environ, {"ATLAS_SOURCE_REVISION": "a" * 40}):
                first = client.get("/healthz")
            with patch.dict(os.environ, {"ATLAS_SOURCE_REVISION": "b" * 40}):
                second = client.get("/healthz")
        for response, revision in ((first, "a" * 40), (second, "b" * 40)):
            self.assertEqual(response.headers.get("cache-control"), "no-store")
            self.assertEqual(response.json()["sourceRevision"], revision)
            self.assertEqual(response.json()["sourceBinding"], "DECLARED")
            self.assertEqual(response.json()["upstreamReadiness"], "UNKNOWN")

    def test_bad_source_revision_stays_unknown(self):
        with patch.dict(os.environ, {"ATLAS_SOURCE_REVISION": "not-a-commit"}):
            with TestClient(app) as client:
                response = client.get("/healthz")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers.get("cache-control"), "no-store")
        self.assertIsNone(response.json()["sourceRevision"])
        self.assertEqual(response.json()["sourceBinding"], "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
