"""Fail-closed, sampled-only operational readiness; no network or provider access."""
from __future__ import annotations

import os
import time
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient
from app import CACHE_SECONDS, _cache, app


class SampleReadinessTests(unittest.TestCase):
    def setUp(self):
        self.original = _cache.copy()
        _cache.clear()
        self.client = TestClient(app)

    def tearDown(self):
        _cache.clear()
        _cache.update(self.original)
        self.client.close()

    def probe(self, revision: str):
        with patch.dict(os.environ, {"ATLAS_SOURCE_REVISION": revision}):
            return self.client.get("/readyz")

    def test_cold_probe_fails_closed_without_scan_or_binding(self):
        response = self.probe("")
        self.assertEqual(response.status_code, 503)
        body = response.json()
        self.assertIs(body["ready"], False)
        self.assertEqual(body["sampleReadiness"], "UNKNOWN")
        self.assertEqual(body["sourceBinding"], "UNKNOWN")
        self.assertEqual(body["releaseReadiness"], "NOT_ATTESTED")
        self.assertEqual(body["scope"], "SAMPLED_PUBLIC_REPOSITORIES_ONLY")
        self.assertEqual(response.headers["cache-control"], "no-store")

    def test_measured_sample_is_not_enough_without_source_binding(self):
        _cache[4] = (time.monotonic(), {"mode": "MEASURED"}, "etag")
        response = self.probe("not-a-full-sha")
        self.assertEqual(response.status_code, 503)
        self.assertIs(response.json()["ready"], False)
        self.assertEqual(response.json()["sampleReadiness"], "MEASURED")

    def test_blocked_stale_and_future_samples_do_not_qualify(self):
        for captured, mode in (
            (time.monotonic(), "BLOCKED"),
            (time.monotonic() - CACHE_SECONDS - 1, "MEASURED"),
            (time.monotonic() + 10, "MEASURED"),
        ):
            with self.subTest(mode=mode, captured=captured):
                _cache.clear()
                _cache[4] = (captured, {"mode": mode}, "etag")
                self.assertEqual(self.probe("a" * 40).status_code, 503)

    def test_fresh_sample_and_declared_revision_is_sample_only(self):
        _cache[4] = (time.monotonic(), {"mode": "MEASURED"}, "etag")
        response = self.probe("b" * 40)
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertIs(body["ready"], True)
        self.assertEqual(body["sourceRevision"], "b" * 40)
        self.assertEqual(body["sourceBinding"], "DECLARED")
        self.assertEqual(body["sampleReadiness"], "MEASURED")
        self.assertEqual(body["upstreamReadiness"], "UNKNOWN")
        self.assertEqual(body["releaseReadiness"], "NOT_ATTESTED")
        self.assertEqual(body["scope"], "SAMPLED_PUBLIC_REPOSITORIES_ONLY")


if __name__ == "__main__":
    unittest.main()
