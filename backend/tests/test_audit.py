from __future__ import annotations

import asyncio
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

import httpx
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app import _cache, allowed_origins, app  # noqa: E402
from audit import AuditError, GitHubReader, scan_organization  # noqa: E402

ORG = "szl-holdings"
REPOS = [".github", "alpha", "beta", "gamma"]


def repo_payload(name: str) -> dict:
    return {
        "name": name, "full_name": f"{ORG}/{name}",
        "description": None, "default_branch": "main", "archived": False,
        "disabled": False, "fork": False, "private": False,
        "language": "Python", "updated_at": "2026-10-17T00:00:00Z",
    }


def github_handler(*, truncated: str | None = None, history_error: str | None = None,
                   empty_repo: str | None = None,
                   org_status: int = 200):
    def handle(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        headers = {
            "x-ratelimit-limit": "5000", "x-ratelimit-remaining": "4900",
            "x-ratelimit-reset": "1792289000",
        }
        if path == f"/orgs/{ORG}":
            if org_status != 200:
                return httpx.Response(org_status, json={"message": "rate limited"}, headers=headers)
            return httpx.Response(200, json={
                "login": ORG, "name": "SZL Holdings", "description": None,
                "html_url": f"https://github.com/{ORG}", "public_repos": 4,
            }, headers=headers)
        if path == f"/orgs/{ORG}/repos":
            return httpx.Response(
                200, json=[{**repo_payload(name), "default_branch": None}
                           if name == empty_repo else repo_payload(name)
                           for name in REPOS], headers=headers,
            )
        for index, name in enumerate(REPOS):
            base = f"/repos/{ORG}/{name}"
            head = format(index + 1, "x") * 40
            tree = format(index + 5, "x") * 40
            if path == base + "/branches/main":
                return httpx.Response(200, json={
                    "protected": True,
                    "commit": {"sha": head, "commit": {"tree": {"sha": tree}}},
                }, headers=headers)
            if path == base + f"/git/trees/{tree}":
                entries = [{"path": "SECURITY.md", "sha": "a" * 40, "type": "blob"}]
                if name == ".github":
                    entries.append({"path": "AGENTS.md", "sha": "b" * 40, "type": "blob"})
                return httpx.Response(200, json={
                    "sha": tree, "truncated": name == truncated, "tree": entries,
                }, headers=headers)
            if path == base + "/community/profile":
                return httpx.Response(200, json={"health_percentage": 80}, headers=headers)
            if path == base + "/rules/branches/main":
                return httpx.Response(404, json={"message": "not found"}, headers=headers)
            if path == base + "/commits":
                if name == history_error:
                    return httpx.Response(503, json={"message": "unavailable"}, headers=headers)
                return httpx.Response(200, json=[], headers=headers)
        return httpx.Response(404, json={"message": "not found"}, headers=headers)
    return handle


async def run_scan(**kwargs) -> dict:
    transport = httpx.MockTransport(github_handler(**kwargs))
    async with httpx.AsyncClient(transport=transport) as client:
        return await scan_organization(GitHubReader(client), 4)


class AuditContractTests(unittest.IsolatedAsyncioTestCase):
    async def test_complete_public_scan_matches_frontend_shape(self):
        result = await run_scan()
        self.assertEqual(result["schemaVersion"], 1)
        self.assertEqual(result["mode"], "MEASURED")
        self.assertIs(result["publicOnly"], True)
        self.assertEqual(result["inventory"]["publicRepos"], 4)
        self.assertEqual(result["sampleSize"], 4)
        self.assertIsNone(result["scores"]["alignment"])
        self.assertEqual(result["repositories"][0]["headSha"], "1" * 40)
        self.assertEqual(result["repositories"][0]["treeSha"], "5" * 40)
        self.assertEqual(result["repositories"][0]["policyHistory"]["status"], "MEASURED")
        self.assertEqual(result["repositories"][0]["policies"][0]["state"], "LOCAL")
        self.assertEqual(result["repositories"][1]["policies"][0]["state"], "ABSENT")
        self.assertEqual(result["rate"]["remaining"], 4900)

    async def test_truncated_tree_blocks_and_preserves_known_sha(self):
        result = await run_scan(truncated="alpha")
        self.assertEqual(result["mode"], "BLOCKED")
        alpha = next(repo for repo in result["repositories"] if repo["name"] == "alpha")
        self.assertEqual(alpha["headSha"], "2" * 40)
        self.assertFalse(alpha["treeComplete"])
        self.assertEqual(alpha["policies"][0]["state"], "UNKNOWN")

    async def test_history_failure_blocks_without_erasing_source(self):
        result = await run_scan(history_error="alpha")
        self.assertEqual(result["mode"], "BLOCKED")
        alpha = next(repo for repo in result["repositories"] if repo["name"] == "alpha")
        self.assertEqual(alpha["headSha"], "2" * 40)
        self.assertEqual(alpha["policies"][2]["state"], "LOCAL")
        self.assertEqual(alpha["policyHistory"]["status"], "BLOCKED")
        self.assertIn("503", alpha["policyHistory"]["error"])

    async def test_empty_repository_blocks_without_aborting_inventory(self):
        result = await run_scan(empty_repo="alpha")
        self.assertEqual(result["mode"], "BLOCKED")
        self.assertEqual(result["sampleSize"], 4)
        alpha = next(repo for repo in result["repositories"] if repo["name"] == "alpha")
        self.assertEqual(alpha["defaultBranch"], "UNKNOWN")
        self.assertIsNone(alpha["headSha"])
        self.assertIsNotNone(alpha["error"])

    async def test_top_level_rate_gate_has_no_fabricated_audit(self):
        transport = httpx.MockTransport(github_handler(org_status=429))
        async with httpx.AsyncClient(transport=transport) as client:
            with self.assertRaises(AuditError) as caught:
                await scan_organization(GitHubReader(client), 4)
        self.assertEqual(caught.exception.status, 429)


class TransportTests(unittest.TestCase):
    def setUp(self):
        _cache.clear()

    def test_health_is_liveness_not_upstream_readiness(self):
        with TestClient(app) as client:
            response = client.get("/healthz")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json()["upstreamReadiness"], "UNKNOWN")

    def test_rejects_other_org_and_invalid_sample_before_upstream(self):
        with TestClient(app) as client:
            self.assertEqual(client.get("/v1/orgs/other/audit").status_code, 404)
            self.assertEqual(
                client.get(f"/v1/orgs/{ORG}/audit?sample_size=2").status_code, 422
            )

    def test_cors_requires_exact_origin(self):
        with patch.dict("os.environ", {"ATLAS_ALLOWED_ORIGINS": "https://atlas.example"}, clear=False):
            self.assertEqual(allowed_origins(), ["https://atlas.example"])
        with patch.dict("os.environ", {"ATLAS_ALLOWED_ORIGINS": "*"}, clear=False):
            with self.assertRaises(RuntimeError):
                allowed_origins()
