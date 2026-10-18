import assert from "node:assert/strict";
import test from "node:test";
import { POLICY_DEFINITIONS } from "./audit.ts";
import {
  BackendAuditError,
  configuredAtlasApiBase,
  parseBackendAudit,
  scanBackendOrganization,
} from "./backend.ts";

function fixture() {
  return {
    schemaVersion: 1,
    mode: "MEASURED",
    publicOnly: true,
    org: { login: "szl-holdings", name: "SZL Holdings", description: null,
      htmlUrl: "https://github.com/szl-holdings", publicRepos: 4 },
    observedAt: "2026-10-17T00:00:00Z",
    startedAt: "2026-10-17T00:00:00Z",
    completedAt: "2026-10-17T00:00:00Z",
    inventory: { publicRepos: 4, active: 4, archived: 0, forks: 0 },
    sampleSize: 4,
    publicInventory: ["a", "b", "c", "d"].map((name) =>
      ({ fullName: "szl-holdings/" + name, archived: false, fork: false, disabled: false })),
    repositories: ["a", "b", "c", "d"].map((name) => ({
      name, fullName: "szl-holdings/" + name, description: null, defaultBranch: "main",
      headSha: "a".repeat(40), treeSha: "b".repeat(40), treeComplete: true,
      protected: true, archived: false, language: null, updatedAt: "2026-10-17T00:00:00Z",
      communityHealth: 80, rulesCount: null, workflowCount: 0,
      policies: POLICY_DEFINITIONS.map((policy) => ({
        key: policy.key, label: policy.label, weight: policy.weight, state: "ABSENT",
        path: null, blobSha: null, sourceRepo: null as string | null,
      })),
      consistency: 100, evidenceCoverage: 100, agentSignals: [],
      policyHistory: { sourceHeadSha: "a".repeat(40), status: "MEASURED",
        commitsExamined: 0, attributedCandidates: 0, detailsExamined: 0,
        unexaminedCandidates: 0, fileListsTruncated: false },
    })),
    scores: { alignment: null, consistency: 100, evidenceCoverage: 100 },
    rate: { limit: 5000, remaining: 4900, resetAt: null },
    sourceUrls: ["https://api.github.com/orgs/szl-holdings"],
    limitations: ["Public repositories only."],
  };
}

test("backend URL is an exact HTTPS origin or local development origin", () => {
  assert.equal(configuredAtlasApiBase(undefined), null);
  assert.equal(configuredAtlasApiBase("https://atlas.example/"), "https://atlas.example");
  assert.equal(configuredAtlasApiBase("http://localhost:7860"), "http://localhost:7860");
  assert.throws(() => configuredAtlasApiBase("http://example.com"), BackendAuditError);
  assert.throws(() => configuredAtlasApiBase("https://user:secret@example.com"), BackendAuditError);
  assert.throws(() => configuredAtlasApiBase("https://example.com/path"), BackendAuditError);
});

test("the API result must preserve exact public source bindings", () => {
  const result = fixture();
  assert.equal(parseBackendAudit(result, 4).mode, "MEASURED");
  result.repositories[0].treeComplete = false;
  assert.throws(() => parseBackendAudit(result, 4), BackendAuditError);
});

test("duplicate or altered policy definitions cannot masquerade as a complete audit", () => {
  const duplicate = fixture();
  duplicate.repositories[0].policies[1] = duplicate.repositories[0].policies[0];
  assert.throws(() => parseBackendAudit(duplicate, 4), BackendAuditError);
  const altered = fixture();
  altered.repositories[0].policies[0].weight = 999;
  assert.throws(() => parseBackendAudit(altered, 4), BackendAuditError);
});

test("partial inherited-policy evidence remains displayable as BLOCKED", () => {
  const partial = fixture();
  partial.mode = "BLOCKED";
  partial.repositories[0].treeComplete = false;
  partial.repositories[0].policyHistory.status = "BLOCKED";
  partial.repositories[0].policies[2].state = "UNKNOWN";
  partial.repositories[0].policies[2].sourceRepo = "szl-holdings/.github";
  assert.equal(parseBackendAudit(partial, 4).mode, "BLOCKED");
});

test("configured API failure does not silently run the browser scanner", async () => {
  let calls = 0;
  const fetcher = (async () => {
    calls += 1;
    return new Response(JSON.stringify({ evidence: "UNAVAILABLE" }), { status: 503 });
  }) as typeof fetch;
  await assert.rejects(
    scanBackendOrganization("https://atlas.example", 4, fetcher),
    /Python API unavailable \(HTTP 503\)/,
  );
  assert.equal(calls, 1);
});

test("valid API response is consumed as AuditResult v1", async () => {
  const fetcher = (async () => Response.json(fixture())) as typeof fetch;
  const result = await scanBackendOrganization("https://atlas.example", 4, fetcher);
  assert.equal(result.repositories.length, 4);
  assert.equal(result.scores.alignment, null);
});
