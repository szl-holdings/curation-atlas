import assert from "node:assert/strict";
import test from "node:test";

import {
  POLICY_DEFINITIONS,
  SNAPSHOT_RESULT,
  canonicalize,
  createReceipt,
  deepInspectionBlocked,
  modeForDeepFailures,
  matchPolicyChanges,
  classifyAgentSignal,
  scanOrganization,
  scoreRepositories,
  type RepoAudit,
} from "./audit.ts";

function repoWithUniqueWorkflow(name: string, workflowFingerprint: string): RepoAudit {
  return {
    name,
    fullName: `example/${name}`,
    description: null,
    defaultBranch: "main",
    headSha: "a".repeat(40),
    treeSha: "b".repeat(40),
    treeComplete: true,
    protected: null,
    archived: false,
    language: null,
    updatedAt: "2026-10-03T00:00:00Z",
    communityHealth: null,
    rulesCount: null,
    workflowCount: 1,
    policies: POLICY_DEFINITIONS.map((definition) => ({
      key: definition.key,
      label: definition.label,
      weight: definition.weight,
      state: definition.key === "workflows" ? "LOCAL" : "UNKNOWN",
      path: definition.key === "workflows" ? ".github/workflows/*" : null,
      blobSha: definition.key === "workflows" ? workflowFingerprint : null,
      sourceRepo: null,
      ...(definition.key === "workflows" ? { memberCount: 1 } : {}),
    })),
    consistency: null,
    evidenceCoverage: 0,
    agentSignals: [],
  };
}

test("a tied set of unique fingerprints cannot receive an arbitrary perfect repository score", () => {
  const repositories = [
    repoWithUniqueWorkflow("alpha", "set:alpha"),
    repoWithUniqueWorkflow("beta", "set:beta"),
    repoWithUniqueWorkflow("gamma", "set:gamma"),
  ];

  scoreRepositories(repositories);

  assert.deepEqual(repositories.map((repository) => repository.consistency), [0, 0, 0]);
});

test("a partial deep scan fails closed", () => {
  assert.equal(modeForDeepFailures(0), "MEASURED");
  assert.equal(modeForDeepFailures(1), "BLOCKED");
  const truncated = repoWithUniqueWorkflow("truncated", "set:truncated");
  truncated.treeComplete = false;
  assert.equal(deepInspectionBlocked(truncated), true);
});

test("the exported receipt digest survives JSON serialization", async () => {
  const receipt = await createReceipt(SNAPSHOT_RESULT);
  const roundTripped = JSON.parse(JSON.stringify(receipt)) as Record<string, unknown>;
  const expected = roundTripped.receiptSha256;
  delete roundTripped.receiptSha256;

  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(canonicalize(roundTripped)),
  );
  const actual = [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");

  assert.equal(actual, expected);
});

test("undefined object members are omitted from canonical JSON", () => {
  assert.equal(canonicalize({ b: undefined, a: 1 }), '{"a":1}');
});

test("policy paths include deleted and renamed candidates with unique policy keys", () => {
  const match = matchPolicyChanges([
    { filename: "docs/retired.md", previous_filename: "SECURITY.md" },
    { filename: ".github/workflows/ci.yml" },
    { filename: ".github/workflows/ci.yaml" },
    { filename: "src/app.ts" },
  ]);
  assert.deepEqual(match.policyKeys, ["security", "workflows"]);
  assert.equal(match.changedPaths.length, 3);
  assert.equal(classifyAgentSignal("example/repo", "", { sha: "a".repeat(40), html_url: "https://github.com/example/repo/commit/" + "a".repeat(40), author: { type: "User", login: "person" }, committer: null, commit: { message: "This looks AI-like" } }), null);
});

test("history failure preserves captured source evidence and blocks the audit", async () => {
  const originalFetch = globalThis.fetch;
  const originalWindow = Object.getOwnPropertyDescriptor(globalThis, "window");
  Object.defineProperty(globalThis, "window", { value: globalThis, configurable: true });
  let failurePhase: "history" | "detail" = "history";
  globalThis.fetch = async (input) => {
    const url = String(input);
    let payload: unknown;
    if (url.includes("/commits?")) {
      if (failurePhase === "history") return new Response(JSON.stringify({ message: "rate limit exceeded" }), { status: 403 });
      return new Response(JSON.stringify(["d", "e"].map((char) => ({ sha: char.repeat(40), html_url: "https://github.com/example/repo/commit/" + char.repeat(40), author: { type: "Bot", login: "automation" }, committer: null, commit: { message: "Update a policy" } }))), { status: 200 });
    }
    if (url.includes("/commits/")) return new Response(JSON.stringify({ message: "rate limit exceeded" }), { status: 403 });
    if (url.includes("/branches/main")) payload = { protected: false, commit: { sha: "a".repeat(40), commit: { tree: { sha: "b".repeat(40) } } } };
    else if (url.includes("/git/trees/")) payload = { truncated: false, tree: [{ path: "SECURITY.md", type: "blob", sha: "c".repeat(40) }] };
    else if (url.includes("/community/profile")) payload = { health_percentage: 100 };
    else if (url.includes("/rules/")) payload = [];
    else if (url.includes("/repos?")) payload = [{ name: "repo", full_name: "example/repo", default_branch: "main", archived: false, disabled: false, fork: false, description: null, language: null, updated_at: "2026-10-07T12:00:00Z" }];
    else payload = { login: "example", name: "Example", description: null, html_url: "https://github.com/example", public_repos: 1 };
    return new Response(JSON.stringify(payload), { status: 200 });
  };
  try {
    const result = await scanOrganization("example", 4, () => {}, () => {});
    assert.equal(result.mode, "BLOCKED");
    assert.equal(result.repositories[0].headSha, "a".repeat(40));
    assert.equal(result.repositories[0].policies.find((policy) => policy.key === "security")?.blobSha, "c".repeat(40));
    assert.equal(result.repositories[0].policyHistory?.status, "BLOCKED");
    failurePhase = "detail";
    const detailFailure = await scanOrganization("example", 4, () => {}, () => {});
    assert.equal(detailFailure.repositories[0].policyHistory?.attributedCandidates, 2);
    assert.equal(detailFailure.repositories[0].policyHistory?.detailsExamined, 0);
    assert.equal(detailFailure.repositories[0].policyHistory?.unexaminedCandidates, 2);
  } finally {
    globalThis.fetch = originalFetch;
    if (originalWindow) Object.defineProperty(globalThis, "window", originalWindow);
    else Reflect.deleteProperty(globalThis, "window");
  }
});
