// Deterministic TypeScript-side vectors for the Python receipt and comparison port.
//
//   node --experimental-strip-types tests/receipts/generate.mts          write ts-fixture.json
//   node --experimental-strip-types tests/receipts/generate.mts --check  exit 1 if it is stale
//
// Every value is synthetic and comes from a seeded PRNG. createReceipt reads the clock,
// so receipts are made under node:test mock timers; lib/ is not modified.
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { mock } from "node:test";
import { fileURLToPath } from "node:url";
import { POLICY_DEFINITIONS, canonicalize, createReceipt, type AuditResult } from "../../lib/audit.ts";
import { compareAudits, projectComparisonAudit } from "../../lib/comparison.ts";

export const TS_FIXTURE_URL = new URL("./ts-fixture.json", import.meta.url);
export const SEED = 20261110;
const ORG = "atlas-synth";
const CLAIM = "Local public GitHub observation and deterministic derivation; not a GitHub attestation or third-party signature.";

type Json = null | boolean | number | string | Json[] | { [key: string]: Json };
type Obj = { [key: string]: Json };
type Rng = () => number;

export function mulberry32(seed: number): Rng {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const int = (rng: Rng, n: number) => Math.floor(rng() * n);
const pick = <T,>(rng: Rng, items: readonly T[]): T => items[int(rng, items.length)];
const sha256 = (text: string) => createHash("sha256").update(text, "utf8").digest("hex");

// ---------------------------------------------------------------- canonical vectors (JSON text in, canonical out)
const NUMBER_LITERALS = [
  "0", "-0", "-0.0", "0.0", "1", "-1", "1.0", "1.50", "100", "1e21", "1E21", "1e+21", "-1e21", "1e20", "123e18",
  "1e-7", "1e-07", "1E-7", "1e-6", "0.000001", "0.0000001", "5e-324", "-5e-324", "2e-323", "4.9406564584124654e-324",
  "2.2250738585072014e-308", "2.225073858507201e-308", "1.7976931348623157e308", "1.7976931348623158e308", "1e308",
  "1e309", "1e400", "-1e400", "9007199254740991", "9007199254740992", "9007199254740993", "-9007199254740993",
  "18014398509481985", "123456789012345678901234567890", "0.1", "0.2", "0.30000000000000004", "4.35", "1.005",
  "0.5", "2.5", "57.49999999999999", "57.5", "1e-5", "12345678901234567", "0.000123", "1.2345e-10", "99999999999999999999",
  "100000000000000000000", "1000000000000000000000", "3.141592653589793", "-273.15", "6.02214076e23",
];

function randomDoubleText(rng: Rng): string {
  const view = new DataView(new ArrayBuffer(8));
  for (;;) {
    view.setUint32(0, Math.floor(rng() * 2 ** 32));
    view.setUint32(4, Math.floor(rng() * 2 ** 32));
    if (rng() < 0.5) view.setUint16(0, (view.getUint16(0) & 0x800f) | ((0x3ff + int(rng, 140) - 70) << 4));
    const value = view.getFloat64(0);
    if (!Number.isFinite(value)) continue;
    const form = int(rng, 4);
    if (form === 0) return String(value);
    if (form === 1) return value.toExponential(int(rng, 20));
    if (form === 2) return value.toPrecision(1 + int(rng, 21));
    return value.toPrecision(17);
  }
}

function numberText(rng: Rng): string {
  return rng() < 0.45 ? pick(rng, NUMBER_LITERALS) : randomDoubleText(rng);
}

const SHORT: Record<number, string> = { 8: "\\b", 9: "\\t", 10: "\\n", 12: "\\f", 13: "\\r", 34: '\\"', 92: "\\\\" };
function unitText(rng: Rng, unit: number, forceEscape: boolean): string {
  const lone = unit >= 0xd800 && unit <= 0xdfff;
  if (unit in SHORT && (forceEscape || rng() < 0.6)) return SHORT[unit];
  if (unit < 0x20 || unit === 34 || unit === 92 || lone || forceEscape || rng() < 0.15) {
    const digits = unit.toString(16).padStart(4, "0");
    return "\\u" + (rng() < 0.5 ? digits : digits.toUpperCase());
  }
  return String.fromCharCode(unit);
}

function stringUnits(rng: Rng, kind: "text" | "key"): number[] {
  const units: number[] = [];
  const length = kind === "key" ? int(rng, 4) : int(rng, 12);
  for (let i = 0; i < length; i += 1) {
    const r = rng();
    if (r < 0.3) units.push(0x20 + int(rng, 95));
    else if (r < 0.38) units.push(int(rng, 0x20));
    else if (r < 0.42) units.push(pick(rng, [0x22, 0x5c, 0x2f, 0x7f, 0x2028, 0x2029, 0xfeff]));
    else if (r < 0.55) units.push(0x80 + int(rng, 0xd800 - 0x80));
    else if (r < 0.65) units.push(0xe000 + int(rng, 0x2000));
    else if (r < 0.75) units.push(0xfb00 + int(rng, 0x500));
    else if (r < 0.88) {
      const cp = 0x10000 + int(rng, 0xfffff);
      units.push(0xd800 + ((cp - 0x10000) >> 10), 0xdc00 + ((cp - 0x10000) & 0x3ff));
    } else units.push(rng() < 0.5 ? 0xd800 + int(rng, 0x400) : 0xdc00 + int(rng, 0x400));
  }
  return units;
}

function stringText(rng: Rng, kind: "text" | "key"): string {
  const special = ["", "__proto__", "constructor", "10", "2", "01", "a", "A", "b", "\u00e9", "e\u0301", "\uff61", "\ud83d\ude00", "\ud800", "\udfff"];
  const chosen = kind === "key" && rng() < 0.35 ? pick(rng, special) : null;
  const units = chosen === null ? stringUnits(rng, kind) : Array.from({ length: chosen.length }, (_, i) => chosen.charCodeAt(i));
  const escapeAll = rng() < 0.1;
  let out = '"';
  for (let i = 0; i < units.length; i += 1) {
    const unit = units[i];
    const next = units[i + 1];
    if (unit >= 0xd800 && unit <= 0xdbff && next !== undefined && next >= 0xdc00 && next <= 0xdfff && !escapeAll && rng() < 0.6) {
      out += String.fromCharCode(unit, next);
      i += 1;
      continue;
    }
    out += unitText(rng, unit, escapeAll);
  }
  return out + '"';
}

function valueText(rng: Rng, depth: number, bias: "number" | "string" | "key" | "nested"): string {
  const r = rng();
  if (depth > 2 || (bias === "number" && r < 0.7)) return numberText(rng);
  if (bias === "string" && r < 0.7) return stringText(rng, "text");
  if (r < 0.15) return pick(rng, ["null", "true", "false"]);
  if (r < 0.3) return numberText(rng);
  if (r < 0.45) return stringText(rng, "text");
  const ws = () => pick(rng, ["", "", "", " ", "\n", "\t", "\r\n "]);
  if (r < 0.65) {
    const items = Array.from({ length: int(rng, 3) }, () => ws() + valueText(rng, depth + 1, bias) + ws());
    return "[" + items.join(",") + "]";
  }
  const members = Array.from({ length: 1 + int(rng, bias === "key" ? 5 : 3) }, () => ws() + stringText(rng, "key") + ws() + ":" + ws() + valueText(rng, depth + 1, bias));
  return "{" + members.join(",") + "}";
}

function canonicalVectors(rng: Rng) {
  const vectors: Array<{ id: string; cls: string; input: string; canonical: string }> = [];
  for (const cls of ["number", "string", "key", "nested"] as const) {
    for (let i = 0; i < 150; i += 1) {
      const input = cls === "key" ? "{" + Array.from({ length: 2 + int(rng, 5) }, () => stringText(rng, "key") + ":" + valueText(rng, 2, "nested")).join(",") + "}" : valueText(rng, cls === "nested" ? 0 : 2, cls);
      const canonical = canonicalize(JSON.parse(input));
      vectors.push({ id: `canon-${cls}-${i}`, cls, input, canonical });
    }
  }
  return vectors;
}

// ---------------------------------------------------------------- synthetic audits
const REPO_NAMES = [".github", "alpha", "beta", "gamma", "delta"];
const BLOBS = ["1".repeat(40), "2".repeat(40), "3".repeat(40), "ab".repeat(20)];
const HEADS = ["a".repeat(40), "a".repeat(40), "b".repeat(40), "A".repeat(40), "abc123def456", null];
const TREES = ["c".repeat(40), "d".repeat(40), null];
const WORKFLOWS = [".github/workflows/ci.yml", ".github/workflows/release.yaml", ".github/workflows/CodeQL.YML", ".github/workflows/notes.txt"];

function mixedCase(rng: Rng, value: string): string {
  return rng() < 0.25 ? [...value].map((c) => (rng() < 0.5 ? c.toUpperCase() : c)).join("") : value;
}

function policy(rng: Rng, definition: (typeof POLICY_DEFINITIONS)[number], repoName: string): Obj {
  const base = { key: definition.key };
  const r = rng();
  if (definition.setPrefix) {
    if (r < 0.3) return { ...base, state: "ABSENT", path: null, blobSha: null, sourceRepo: null, ...(rng() < 0.5 ? { memberCount: rng() < 0.9 ? 0 : 1 } : {}) };
    if (r < 0.85) {
      const names = [...new Set(Array.from({ length: 1 + int(rng, 2) }, () => (rng() < 0.9 ? pick(rng, WORKFLOWS.slice(0, 2)) : pick(rng, WORKFLOWS))))];
      const members = names.map((name) => `${name}:${rng() < 0.95 ? pick(rng, BLOBS.slice(0, 2)) : "short"}`);
      return { ...base, state: "LOCAL", path: rng() < 0.95 ? ".github/workflows/*" : ".github/workflows", blobSha: "set:" + members.join("|"), sourceRepo: null, memberCount: rng() < 0.92 ? members.length : members.length + 1 };
    }
    return { ...base, state: "UNKNOWN", path: null, blobSha: null, sourceRepo: null };
  }
  const github = repoName === ".github";
  if (r < 0.35) return { ...base, state: "ABSENT", path: null, blobSha: null, sourceRepo: rng() < 0.97 ? null : `${ORG}/.github` };
  if (r < 0.75 || github) {
    return {
      ...base,
      state: "LOCAL",
      path: rng() < 0.95 ? (github || rng() < 0.7 ? definition.candidates[0] : pick(rng, definition.candidates)) : "README.md",
      blobSha: rng() < 0.95 ? (github || rng() < 0.6 ? BLOBS[0] : pick(rng, BLOBS)) : "abc",
      sourceRepo: null,
    };
  }
  if (r < 0.88) {
    return { ...base, state: "INHERITED", path: definition.candidates[0], blobSha: rng() < 0.8 ? BLOBS[0] : pick(rng, BLOBS), sourceRepo: rng() < 0.9 ? mixedCase(rng, `${ORG}/.github`) : `${ORG}/alpha` };
  }
  return { ...base, state: "UNKNOWN", path: null, blobSha: null, sourceRepo: null };
}

function shuffle<T>(rng: Rng, items: T[]): T[] {
  for (let i = items.length - 1; i > 0; i -= 1) {
    const j = int(rng, i + 1);
    [items[i], items[j]] = [items[j], items[i]];
  }
  return items;
}

function timestamp(rng: Rng, day: number): string {
  const hh = String(int(rng, 24)).padStart(2, "0");
  const mm = String(int(rng, 60)).padStart(2, "0");
  const ss = String(int(rng, 60)).padStart(2, "0");
  const fraction = pick(rng, ["", "", `.${String(int(rng, 1000)).padStart(3, "0")}`, ".5"]);
  const zone = pick(rng, ["Z", "Z", "Z", "+02:00", "-05:30", "+00:00"]);
  return `2026-10-${String(day).padStart(2, "0")}T${hh}:${mm}:${ss}${fraction}${zone}`;
}

function audit(rng: Rng, org: string, day: number, size: number): Obj {
  const names = shuffle(rng, [...REPO_NAMES]).slice(0, size);
  const repositories: Json[] = names.map((name) => ({
    name,
    fullName: mixedCase(rng, `${org}/${name}`),
    headSha: pick(rng, HEADS),
    treeSha: rng() < 0.9 ? pick(rng, TREES.slice(0, 2)) : null,
    treeComplete: rng() < 0.9,
    policies: shuffle(rng, POLICY_DEFINITIONS.map((definition) => policy(rng, definition, name))),
    ...(rng() < 0.06 ? { error: "GitHub returned 403 for the tree read." } : {}),
  }));
  return {
    schemaVersion: 1,
    mode: rng() < 0.75 ? "MEASURED" : pick(rng, ["SAMPLE", "BLOCKED", "UNAVAILABLE"]),
    publicOnly: true,
    org: { login: mixedCase(rng, org) },
    observedAt: timestamp(rng, day),
    repositories,
  };
}

function stressFields(rng: Rng): Obj {
  const numbers = [-0, 1e21, 1e-7, 5e-324, 2 ** 53 + 1, NaN, Infinity, -Infinity, 0.1 + 0.2, 1.7976931348623157e308, 57.49999999999999];
  const text = () => JSON.parse(stringText(rng, "text")) as string;
  return {
    scores: { alignment: null, consistency: rng() < 0.5 ? null : pick(rng, numbers), evidenceCoverage: pick(rng, numbers) },
    limitations: Array.from({ length: int(rng, 3) }, text),
    extra: Object.fromEntries(Array.from({ length: int(rng, 3) }, () => [JSON.parse(stringText(rng, "key")) as string, rng() < 0.5 ? text() : pick(rng, numbers)])),
  };
}

async function withClock<T>(iso: string, run: () => Promise<T>): Promise<T> {
  mock.timers.enable({ apis: ["Date"], now: Date.parse(iso) });
  try {
    return await run();
  } finally {
    mock.timers.reset();
  }
}

function generatedAt(rng: Rng): string {
  return new Date(Date.UTC(2026, 9, 1 + int(rng, 30), int(rng, 24), int(rng, 60), int(rng, 60), int(rng, 1000))).toISOString();
}

async function receipts(rng: Rng) {
  const out: Array<{ id: string; generatedAt: string; receiptSha256: string; text: string }> = [];
  for (let i = 0; i < 200; i += 1) {
    const size = pick(rng, [0, 0, 0, 0, 0, 0, 1, 2]);
    const value = { ...audit(rng, ORG, 1 + int(rng, 28), size), ...stressFields(rng) } as unknown as AuditResult;
    const at = generatedAt(rng);
    const receipt = await withClock(at, () => createReceipt(value));
    // The first ten use the app's export format (JSON.stringify(receipt, null, 2)); the rest are compact.
    const text = i < 10 ? JSON.stringify(receipt, null, 2) : JSON.stringify(receipt);
    out.push({ id: `ts-receipt-${i}`, generatedAt: at, receiptSha256: receipt.receiptSha256, text });
  }
  return out;
}

// ---------------------------------------------------------------- comparison vectors
const CODES: Record<string, string> = {
  ADDED: "A",
  REMOVED: "R",
  UNCHANGED: "U",
  UNKNOWN: "K",
  "CHANGED:The observed content or workflow-set fingerprint differs.": "C",
  "CHANGED:The policy location or inheritance changed while the observed fingerprint matches.": "L",
};
export function changeCode(change: string, reason: string): string {
  const code = CODES[change] ?? CODES[`${change}:${reason}`];
  if (!code) throw new Error(`unmapped change ${change}: ${reason}`);
  return code;
}

function comparisons(rng: Rng) {
  // Pool order is observation order (day i + 1), so most pairs compare an older baseline with a newer audit.
  const pool: Obj[] = [];
  for (let i = 0; i < 28; i += 1) pool.push(audit(rng, i % 14 === 13 ? "other-org" : ORG, 1 + i, 1 + int(rng, 4)));
  const vectors: Array<Record<string, Json>> = [];
  for (let i = 0; i < 400; i += 1) {
    const previous = int(rng, pool.length);
    const current = rng() < 0.85 ? previous + int(rng, pool.length - previous) : int(rng, pool.length);
    try {
      const result = compareAudits(projectComparisonAudit(pool[previous]), pool[current] as unknown as AuditResult);
      vectors.push({
        id: `compare-${i}`,
        previous,
        current,
        overlapCount: result.overlapCount,
        changedRevisionCount: result.changedRevisionCount,
        enteredCohort: result.enteredCohort,
        leftCohort: result.leftCohort,
        changes: result.deltas.map((delta) => changeCode(delta.change, delta.reason)).join(""),
      });
    } catch (error) {
      vectors.push({ id: `compare-${i}`, previous, current, error: error instanceof Error ? error.message : String(error) });
    }
  }
  return { pool, vectors };
}

// ---------------------------------------------------------------- P15-D5: inputs the TS verifier accepts and the Python port refuses
async function sealed(payload: Obj): Promise<string> {
  const digest = sha256(canonicalize(payload));
  return JSON.stringify({ ...payload, receiptSha256: digest });
}

function baseAudit(): Obj {
  const rng = mulberry32(SEED + 5);
  const value = audit(rng, ORG, 7, 1);
  value.mode = "MEASURED";
  value.observedAt = "2026-10-07T12:00:00Z";
  return value;
}

async function divergences() {
  const at = "2026-10-08T09:30:00.000Z";
  const envelope = (value: Obj, overrides: Obj = {}): Obj => ({ receiptSchema: "curation-atlas/1", generatedAt: at, claim: CLAIM, audit: value, ...overrides });
  const withAudit = (change: (value: Obj) => void) => {
    const value = baseAudit();
    change(value);
    return envelope(value);
  };
  const firstPolicy = (value: Obj) => ((value.repositories as Obj[])[0].policies as Obj[])[0];
  const cases: Array<[string, string, Obj]> = [
    ["D5-mode-array", "invalid_mode", withAudit((value) => { value.mode = ["MEASURED"]; })],
    ["D5-state-array", "invalid_state", withAudit((value) => { firstPolicy(value).state = ["LOCAL"]; })],
    ["D5-local-time", "invalid_timestamp", withAudit((value) => { value.observedAt = "2026-10-07T12:00:00"; })],
    ["D5-impossible-date", "invalid_timestamp", withAudit((value) => { value.observedAt = "2026-02-30T00:00:00Z"; })],
    ["D5-hour-24", "invalid_timestamp", withAudit((value) => { value.observedAt = "2026-10-07T24:00:00Z"; })],
    ["D5-no-seconds", "invalid_timestamp", withAudit((value) => { value.observedAt = "2026-10-07T12:00"; })],
    ["D5-compact-offset", "invalid_timestamp", withAudit((value) => { value.observedAt = "2026-10-07T12:00:00+0530"; })],
    ["D5-lowercase-z", "invalid_timestamp", withAudit((value) => { value.observedAt = "2026-10-07T12:00:00z"; })],
    ["D5-long-fraction", "invalid_timestamp", withAudit((value) => { value.observedAt = "2026-10-07T12:00:00.123456Z"; })],
    ["D5-year-range", "invalid_timestamp", withAudit((value) => { value.observedAt = "0000-01-01T00:00:00Z"; })],
    ["D5-generated-at", "invalid_generated_at", envelope(baseAudit(), { generatedAt: 12345 })],
    ["D5-claim", "invalid_claim", envelope(baseAudit(), { claim: "Signed GitHub attestation." })],
    ["D5-extra-envelope-key", "unknown_envelope_key", envelope(baseAudit(), { signature: "not-a-signature" })],
    ["D5-non-ascii-login", "invalid_org", withAudit((value) => { (value.org as Obj).login = "\u212aaren"; for (const repo of value.repositories as Obj[]) repo.fullName = `karen/${repo.name as string}`; })],
    ["D5-non-ascii-repo", "invalid_repository", withAudit((value) => { (value.org as Obj).login = "karen"; for (const repo of value.repositories as Obj[]) repo.fullName = `\u212aaren/${repo.name as string}`; })],
  ];
  const out: Array<Record<string, Json>> = [];
  for (const [id, code, payload] of cases) out.push({ id, decision: "P15-D5", kind: "receipt", pythonCode: code, text: await sealed(payload) });
  // Duplicate key: JSON.parse keeps the last "mode"; the earlier one is outside the digest.
  const duplicate = (await sealed(envelope(baseAudit()))).replace('"mode":"MEASURED"', '"mode":"SAMPLE","mode":"MEASURED"');
  out.push({ id: "D5-duplicate-key", decision: "P15-D5", kind: "receipt", pythonCode: "duplicate_key", text: duplicate });
  // Empty error string: TS !repository.error treats it as no error, so the repository is pinned.
  const before = baseAudit();
  const repo = (before.repositories as Obj[])[0];
  Object.assign(repo, { headSha: "a".repeat(40), treeSha: "c".repeat(40), treeComplete: true, error: "" });
  for (const item of repo.policies as Obj[]) if (item.key !== "workflows") Object.assign(item, { state: "ABSENT", path: null, blobSha: null, sourceRepo: null });
  const after = structuredClone(before);
  after.observedAt = "2026-10-07T13:00:00Z";
  const comparison = compareAudits(projectComparisonAudit(before), after as unknown as AuditResult);
  const tsChanges = comparison.deltas.filter((delta) => delta.fullName === String(repo.fullName).toLowerCase()).map((delta) => changeCode(delta.change, delta.reason)).join("");
  out.push({ id: "D5-empty-error", decision: "P15-D5", kind: "compare", previous: before, current: after, tsChanges, tsChangedRevisionCount: comparison.changedRevisionCount });
  return out;
}

export async function buildTsFixture() {
  const rng = mulberry32(SEED);
  const { pool, vectors } = comparisons(rng);
  return {
    schema: "curation-atlas/receipt-vectors/1",
    generator: "tests/receipts/generate.mts",
    seed: SEED,
    policyDefinitions: POLICY_DEFINITIONS,
    canonicalVectors: canonicalVectors(rng),
    receipts: await receipts(rng),
    comparisonPool: pool,
    comparisonVectors: vectors,
    divergences: await divergences(),
  };
}

// One array element per line keeps diffs reviewable.
export function fixtureText(fixture: Record<string, unknown>): string {
  const lines = Object.entries(fixture).map(([key, value]) => {
    const head = `  ${JSON.stringify(key)}: `;
    if (!Array.isArray(value)) return head + JSON.stringify(value);
    return head + "[\n" + value.map((item) => "    " + JSON.stringify(item)).join(",\n") + "\n  ]";
  });
  return "{\n" + lines.join(",\n") + "\n}\n";
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const text = fixtureText(await buildTsFixture());
  const path = fileURLToPath(TS_FIXTURE_URL);
  if (process.argv.includes("--check")) {
    let current = "";
    try {
      current = readFileSync(path, "utf8");
    } catch {
      // A missing fixture is stale.
    }
    if (current !== text) {
      console.error(`${path} is stale: run node --experimental-strip-types tests/receipts/generate.mts`);
      process.exit(1);
    }
    console.log(`${path} is current`);
  } else {
    writeFileSync(path, text);
    console.log(`wrote ${path}`);
  }
}
