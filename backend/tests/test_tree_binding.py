import unittest

import httpx

from test_audit import github_handler
from audit import GitHubReader, scan_organization


class TreeCoverageTests(unittest.IsolatedAsyncioTestCase):
    async def test_unknown_tree_coverage_is_not_promoted_to_complete(self):
        for coverage in ("missing", None, 0, ""):
            with self.subTest(coverage=coverage):
                original = github_handler()

                def handler(request):
                    response = original(request)
                    if "/git/trees/" in request.url.path:
                        payload = response.json()
                        if coverage == "missing":
                            payload.pop("truncated")
                        else:
                            payload["truncated"] = coverage
                        return httpx.Response(200, json=payload, headers=response.headers)
                    return response

                async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
                    result = await scan_organization(GitHubReader(client), 4)
                self.assertEqual(result["mode"], "BLOCKED")
                for repo in result["repositories"]:
                    self.assertFalse(repo["treeComplete"])
                    self.assertTrue(all(p["state"] == "UNKNOWN" for p in repo["policies"]))
