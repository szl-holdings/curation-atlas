import assert from "node:assert/strict";
import test from "node:test";
import { SNAPSHOT_RESULT, createReceipt, type AuditResult } from "./audit.ts";
import { compareAudits, projectComparisonAudit, verifyImportedReceipt } from "./comparison.ts";

function fixture(): AuditResult {
  const value = structuredClone(SNAPSHOT_RESULT);
  value.mode = "MEASURED";
  value.observedAt = "2026-10-07T12:00:00Z";
  for (const repository of value.repositories) {
    repository.headSha = "a".repeat(40);
    repository.treeSha = "b".repeat(40);
    repository.treeComplete = true;
    const policy = repository.policies.find((policy) => policy.key === "security")!;
    Object.assign(policy, { state: "ABSENT", path: null, blobSha: null, sourceRepo: null });
  }
  return value;
}

test("receipt import verifies the full envelope and rejects content tampering", async () => {
  const envelope = await createReceipt(fixture());
  assert.equal((await verifyImportedReceipt(JSON.stringify(envelope))).audit.orgLogin, "szl-holdings");
  envelope.audit.org.name = "tampered";
  await assert.rejects(verifyImportedReceipt(JSON.stringify(envelope)), /digest does not match/);
});

test("comparison distinguishes addition, incomplete source, and cohort departure", () => {
  const before = fixture();
  const after = structuredClone(before);
  after.observedAt = "2026-10-07T13:00:00Z";
  const added = after.repositories[0].policies.find((policy) => policy.key === "security")!;
  Object.assign(added, { state: "LOCAL", path: "SECURITY.md", blobSha: "c".repeat(40) });
  after.repositories[1].treeComplete = false;
  const left = after.repositories.pop()!;
  const result = compareAudits(projectComparisonAudit(before), after);
  assert.equal(result.deltas.find((delta) => delta.fullName === after.repositories[0].fullName && delta.key === "security")?.change, "ADDED");
  assert.equal(result.deltas.find((delta) => delta.fullName === after.repositories[1].fullName && delta.key === "security")?.change, "UNKNOWN");
  assert.deepEqual(result.leftCohort, [left.fullName]);
});

test("SAMPLE and short-head inputs never establish policy transitions", () => {
  const before = fixture();
  const after = structuredClone(before);
  before.mode = "SAMPLE";
  assert.ok(compareAudits(projectComparisonAudit(before), after).deltas.every((delta) => delta.change === "UNKNOWN"));
  before.mode = "MEASURED";
  before.repositories[0].headSha = "a".repeat(12);
  assert.ok(compareAudits(projectComparisonAudit(before), after).deltas.filter((delta) => delta.fullName === before.repositories[0].fullName).every((delta) => delta.change === "UNKNOWN"));
});

test("comparison rejects a different organization, newer baseline, and duplicate identities", () => {
  const before = fixture();
  const newer = structuredClone(before);
  newer.observedAt = "2026-10-08T12:00:00Z";
  assert.throws(() => compareAudits(projectComparisonAudit(newer), before), /newer/);
  const projected = projectComparisonAudit(before);
  projected.orgLogin = "different";
  assert.throws(() => compareAudits(projected, before), /same organization/);
  before.repositories.push(before.repositories[0]);
  assert.throws(() => projectComparisonAudit(before), /repeats/);
});

test("workflow count equality cannot hide changed file fingerprints", () => {
  const before = fixture();
  const after = structuredClone(before);
  const old = before.repositories[0].policies.find((policy) => policy.key === "workflows")!;
  const next = after.repositories[0].policies.find((policy) => policy.key === "workflows")!;
  Object.assign(old, { state: "LOCAL", path: ".github/workflows/*", blobSha: "set:.github/workflows/ci.yml:" + "c".repeat(40), memberCount: 1 });
  Object.assign(next, { state: "LOCAL", path: ".github/workflows/*", blobSha: "set:.github/workflows/ci.yml:" + "d".repeat(40), memberCount: 1 });
  assert.equal(compareAudits(projectComparisonAudit(before), after).deltas.find((delta) => delta.fullName === before.repositories[0].fullName && delta.key === "workflows")?.change, "CHANGED");
});

test("unsupported inheritance and malformed workflow sets cannot establish transitions", () => {
  const before = fixture();
  const after = structuredClone(before);
  const malformed = before.repositories[1].policies.find((policy) => policy.key === "workflows")!;
  Object.assign(malformed, { state: "LOCAL", path: ".github/workflows/*", blobSha: "set:garbage", memberCount: 1 });
  const inherited = before.repositories[1].policies.find((policy) => policy.key === "codeowners")!;
  Object.assign(inherited, { state: "INHERITED", path: ".github/CODEOWNERS", blobSha: "c".repeat(40), sourceRepo: "szl-holdings/.github" });
  const result = compareAudits(projectComparisonAudit(before), after);
  assert.equal(result.deltas.find((delta) => delta.fullName === before.repositories[1].fullName && delta.key === "workflows")?.change, "UNKNOWN");
  assert.equal(result.deltas.find((delta) => delta.fullName === before.repositories[1].fullName && delta.key === "codeowners")?.change, "UNKNOWN");
});

test("optional absent counts do not create drift and invalid absent counts stay unknown", () => {
  const before = fixture();
  const after = structuredClone(before);
  const old = before.repositories[0].policies.find((policy) => policy.key === "workflows")!;
  const next = after.repositories[0].policies.find((policy) => policy.key === "workflows")!;
  Object.assign(old, { state: "ABSENT", path: null, blobSha: null, sourceRepo: null, memberCount: 0 });
  Object.assign(next, { state: "ABSENT", path: null, blobSha: null, sourceRepo: null });
  delete next.memberCount;
  assert.equal(compareAudits(projectComparisonAudit(before), after).deltas.find((delta) => delta.fullName === before.repositories[0].fullName && delta.key === "workflows")?.change, "UNCHANGED");
  old.memberCount = 1;
  assert.equal(compareAudits(projectComparisonAudit(before), after).deltas.find((delta) => delta.fullName === before.repositories[0].fullName && delta.key === "workflows")?.change, "UNKNOWN");
});
