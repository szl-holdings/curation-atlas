import assert from "node:assert/strict";
import test from "node:test";
import { scanOrganization } from "./audit.ts";

async function scanWithTree(tree: Record<string, unknown>, branchSha = "a".repeat(40)) {
  const originalFetch = globalThis.fetch;
  const originalWindow = Object.getOwnPropertyDescriptor(globalThis, "window");
  Object.defineProperty(globalThis, "window", { value: globalThis, configurable: true });
  globalThis.fetch = async (input) => {
    const url = String(input);
    let payload: unknown;
    if (url.includes("/branches/main")) payload = { protected: false, commit: { sha: branchSha, commit: { tree: { sha: "b".repeat(40) } } } };
    else if (url.includes("/git/trees/")) payload = tree;
    else if (url.includes("/community/profile")) payload = { health_percentage: 100 };
    else if (url.includes("/rules/") || url.includes("/commits?")) payload = [];
    else if (url.includes("/repos?")) payload = [{ name: "repo", full_name: "example/repo", default_branch: "main", archived: false, disabled: false, fork: false, description: null, language: null, updated_at: "2026-10-07T12:00:00Z" }];
    else payload = { login: "example", name: "Example", description: null, html_url: "https://github.com/example", public_repos: 1 };
    return new Response(JSON.stringify(payload), { status: 200 });
  };
  try {
    return await scanOrganization("example", 4, () => {}, () => {});
  } finally {
    globalThis.fetch = originalFetch;
    if (originalWindow) Object.defineProperty(globalThis, "window", originalWindow);
    else Reflect.deleteProperty(globalThis, "window");
  }
}

const validTree = {
  sha: "b".repeat(40), truncated: false,
  tree: [{ path: "SECURITY.md", type: "blob", sha: "c".repeat(40) }],
};

test("browser audit rejects unbound trees and unknown coverage", async (t) => {
  for (const [label, changes] of [
    ["different tree", { sha: "d".repeat(40) }],
    ["missing tree identity", { sha: undefined }],
    ["missing coverage", { truncated: undefined }],
    ["null coverage", { truncated: null }],
    ["numeric coverage", { truncated: 0 }],
    ["empty string coverage", { truncated: "" }],
  ] as const) {
    await t.test(label, async () => {
      const result = await scanWithTree({ ...validTree, ...changes });
      assert.equal(result.mode, "BLOCKED");
      assert.equal(result.repositories[0].treeComplete, false);
      assert.equal(result.repositories[0].policies.find((p) => p.key === "security")?.state, "UNKNOWN");
    });
  }
});

test("browser audit requires exact branch identity before claiming measured evidence", async () => {
  const result = await scanWithTree(validTree, "not-a-commit");
  assert.equal(result.mode, "BLOCKED");
});

test("matching complete and explicitly truncated trees retain their coverage", async () => {
  assert.equal((await scanWithTree(validTree)).mode, "MEASURED");
  const truncated = await scanWithTree({ ...validTree, truncated: true });
  assert.equal(truncated.mode, "BLOCKED");
  assert.equal(truncated.repositories[0].treeSha, validTree.sha);
});
