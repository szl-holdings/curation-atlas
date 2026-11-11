// Cross-language receipt check: receipts made by backend/receipt.py must verify here, and the
// TypeScript-made vectors that backend/tests/ checks must still match what lib/ produces.
// A missing vector file fails the run; nothing here is skipped.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test, { mock } from "node:test";
import { buildTsFixture, changeCode, fixtureText, TS_FIXTURE_URL } from "../tests/receipts/generate.mts";
import { createReceipt, type AuditResult } from "./audit.ts";
import { compareAudits, projectComparisonAudit, verifyImportedReceipt } from "./comparison.ts";

type PyReceipt = { id: string; generatedAt: string; receiptSha256: string; text: string };
type Divergence = { id: string; decision: string; kind: "receipt" | "compare"; text?: string; previous?: AuditResult; current?: AuditResult; tsChanges?: string };

const pyFixture = JSON.parse(readFileSync(new URL("../tests/receipts/py-fixture.json", import.meta.url), "utf8")) as { receipts: PyReceipt[] };
const tsFixture = JSON.parse(readFileSync(TS_FIXTURE_URL, "utf8")) as { divergences: Divergence[] };

test("receipts made by the Python port verify here, 200 of 200, with identical digests", async () => {
  assert.equal(pyFixture.receipts.length, 200);
  let verified = 0;
  let recreated = 0;
  for (const item of pyFixture.receipts) {
    const result = await verifyImportedReceipt(item.text);
    assert.equal(result.receiptSha256, item.receiptSha256, item.id);
    verified += 1;
    mock.timers.enable({ apis: ["Date"], now: Date.parse(item.generatedAt) });
    try {
      const again = await createReceipt((JSON.parse(item.text) as { audit: AuditResult }).audit);
      assert.equal(again.generatedAt, item.generatedAt, item.id);
      assert.equal(again.receiptSha256, item.receiptSha256, item.id);
      recreated += 1;
    } finally {
      mock.timers.reset();
    }
  }
  assert.deepEqual([verified, recreated], [200, 200]);
});

test("the committed TypeScript vectors match what lib/ produces now", async () => {
  assert.equal(readFileSync(TS_FIXTURE_URL, "utf8"), fixtureText(await buildTsFixture()), "run node --experimental-strip-types tests/receipts/generate.mts");
});

test("P15-D5: this verifier accepts every input the Python port refuses", async () => {
  const receipts = tsFixture.divergences.filter((item) => item.kind === "receipt");
  assert.equal(receipts.length, 16);
  for (const item of receipts) {
    assert.equal(item.decision, "P15-D5");
    await assert.doesNotReject(verifyImportedReceipt(item.text ?? ""), item.id);
  }
  const empty = tsFixture.divergences.find((item) => item.id === "D5-empty-error");
  assert.ok(empty?.previous && empty.current);
  const result = compareAudits(projectComparisonAudit(empty.previous), empty.current);
  const name = projectComparisonAudit(empty.previous).repositories[0].fullName;
  const changes = result.deltas.filter((delta) => delta.fullName === name).map((delta) => changeCode(delta.change, delta.reason)).join("");
  assert.equal(changes, empty.tsChanges);
  assert.notEqual(changes, "K".repeat(10));
});
