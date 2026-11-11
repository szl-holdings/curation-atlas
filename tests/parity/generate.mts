// Generates TS/Python parity vectors from lib/audit.ts.
//
//   node --experimental-strip-types tests/parity/generate.mts          # rewrite tests/parity/vectors/*.json
//   node --experimental-strip-types tests/parity/generate.mts --check  # fail if the committed vectors are stale
//
// Every vector holds a synthetic input and the output that lib/audit.ts produced for it. The
// Python side (backend/tests/test_parity.py) recomputes each output with backend/audit.py and
// compares. Inputs are synthetic: no network, no GitHub data, no clock (timestamps are projected
// out). A seeded PRNG makes the output byte-for-byte reproducible on one Node/ICU build.
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  POLICY_DEFINITIONS,
  classifyAgentSignal,
  matchPolicyChanges,
  resolvePolicies,
  scanOrganization,
  scoreRepositories,
  type PolicyState,
  type RepoAudit,
} from "../../lib/audit.ts";

type Json = null | boolean | number | string | Json[] | { [key: string]: Json };
type JsonObject = { [key: string]: Json };
type Vector = { id: string; stratum: string; input: Json; ts: Json };

const SCHEMA = "curation-atlas.parity-vectors/v1";
const SEED = 20261110;
const ORG = "szl-holdings";
const VECTOR_DIR = join(dirname(fileURLToPath(import.meta.url)), "vectors");

// ---------------------------------------------------------------------------------------------
// Deterministic helpers

function prng(seed: number) {
  let state = seed >>> 0;
  const next = () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  const int = (low: number, high: number) => low + Math.floor(next() * (high - low + 1));
  const pick = <T,>(items: readonly T[]): T => items[Math.floor(next() * items.length)];
  const chance = (p: number) => next() < p;
  const shuffle = <T,>(items: T[]): T[] => {
    for (let i = items.length - 1; i > 0; i -= 1) {
      const j = Math.floor(next() * (i + 1));
      [items[i], items[j]] = [items[j], items[i]];
    }
    return items;
  };
  return { next, int, pick, chance, shuffle };
}

const sha1 = (text: string) => createHash("sha1").update(text, "utf8").digest("hex");

// Wire form shared with the Python side: plain JSON, except that non-finite numbers and
// negative zero are tagged as {"$float": ...} so they survive JSON; undefined members are
// dropped (JSON semantics) and thrown errors become {"$error": <constructor name>}.
function wire(value: unknown): Json {
  if (value === null || value === undefined) return null;
  if (typeof value === "number") {
    if (Number.isNaN(value)) return { $float: "nan" };
    if (value === Infinity) return { $float: "inf" };
    if (value === -Infinity) return { $float: "-inf" };
    if (Object.is(value, -0)) return { $float: "-0" };
    return value;
  }
  if (typeof value === "string" || typeof value === "boolean") return value;
  if (Array.isArray(value)) return value.map((item) => wire(item));
  if (typeof value === "object") {
    const out: JsonObject = {};
    const record = value as Record<string, unknown>;
    for (const key of Object.keys(record).sort()) {
      if (record[key] !== undefined) out[key] = wire(record[key]);
    }
    return out;
  }
  throw new Error(`parity generator cannot encode a ${typeof value}`);
}

function unwire(value: Json): unknown {
  if (Array.isArray(value)) return value.map(unwire);
  if (value !== null && typeof value === "object") {
    const keys = Object.keys(value);
    if (keys.length === 1 && keys[0] === "$float") {
      const tag = value.$float;
      if (tag === "nan") return NaN;
      if (tag === "inf") return Infinity;
      if (tag === "-inf") return -Infinity;
      if (tag === "-0") return -0;
      throw new Error(`unknown $float tag ${String(tag)}`);
    }
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, unwire(item)]));
  }
  return value;
}

// TS runs on exactly the bytes that are written: the stored input is re-parsed first.
function frozen(input: Json): unknown {
  return unwire(JSON.parse(JSON.stringify(input)) as Json);
}

function errorOf(error: unknown): Json {
  return { $error: error instanceof Error ? error.constructor.name : typeof error };
}

function capture(run: () => unknown): Json {
  try {
    return wire(run());
  } catch (error) {
    return errorOf(error);
  }
}

// ---------------------------------------------------------------------------------------------
// js_round <-> Math.round (backend/audit.py js_round is the twin of the TS Math.round calls)

function jsRoundVectors(): Vector[] {
  const r = prng(SEED + 1);
  const values: Array<[string, number]> = [];
  for (let k = 0; k < 100; k += 1) values.push(["in_domain", k + 0.5]);
  for (let k = 0; k <= 100; k += 5) values.push(["in_domain", k]);
  while (values.length < 320) {
    const b = r.int(1, 64);
    const a = r.int(0, b);
    values.push(["in_domain", r.chance(0.5) ? (a / b) * 100 : (100 * a) / b]);
  }
  const edges = [
    -0, -0.4, -0.5, -0.6, -1.5, -2.5, -3.5, -1e-300, 0.49999999999999994, 5e-324, 1e-300,
    2 ** 52 - 0.5, 2 ** 52 + 1, 2 ** 52 + 3, 2 ** 53 + 2, 2 ** 60 + 4096, 1e21, 1e300,
    Number.MAX_VALUE, NaN, Infinity, -Infinity,
  ];
  for (const edge of edges) values.push(["out_of_domain", edge]);
  while (values.length < 520) {
    const kind = r.int(0, 2);
    if (kind === 0) values.push(["out_of_domain", -r.int(0, 200) - r.pick([0, 0.5, 0.25, 0.75])]);
    else if (kind === 1) values.push(["out_of_domain", 2 ** 52 + r.int(0, 2 ** 20) * r.pick([1, 2])]);
    else values.push(["out_of_domain", r.next() * 10 ** r.int(16, 300)]);
  }
  return values.map(([stratum, value], index) => {
    const input = wire(value);
    return { id: `round-${index}`, stratum, input, ts: capture(() => Math.round(frozen(input) as number)) };
  });
}

// ---------------------------------------------------------------------------------------------
// scoreRepositories <-> score_repositories
// Compact input: repos[i] = 10 [stateLetter, blobSha] pairs in POLICY_DEFINITIONS order;
// optional perm reorders each repo's policy list. Both sides expand it the same way.

const STATE: Record<string, PolicyState> = { L: "LOCAL", I: "INHERITED", A: "ABSENT", U: "UNKNOWN" };

function expandRepos(input: { repos: Array<Array<[string, string | null]>>; perm: number[] | null }): RepoAudit[] {
  return input.repos.map((row, index) => {
    let policies = POLICY_DEFINITIONS.map((definition, k) => {
      const [letter, blobSha] = row[k];
      return {
        key: definition.key,
        label: definition.label,
        weight: definition.weight,
        state: STATE[letter],
        path: letter === "L" || letter === "I" ? "p" : null,
        blobSha,
        sourceRepo: letter === "I" ? `${ORG}/.github` : null,
      };
    });
    if (input.perm) policies = input.perm.map((k) => policies[k]);
    return {
      name: `r${index}`,
      fullName: `${ORG}/r${index}`,
      description: null,
      defaultBranch: "main",
      headSha: null,
      treeSha: null,
      treeComplete: true,
      protected: null,
      archived: false,
      language: null,
      updatedAt: "2026-11-10T00:00:00Z",
      communityHealth: null,
      rulesCount: null,
      workflowCount: 0,
      policies,
      consistency: null,
      evidenceCoverage: 0,
      agentSignals: [],
    };
  });
}

function scoreVectors(): Vector[] {
  const r = prng(SEED + 2);
  const out: Vector[] = [];
  const plan: Array<[string, number]> = [["in_domain", 380], ["shuffled_order", 60], ["empty_sha", 80]];
  for (const [stratum, count] of plan) {
    for (let n = 0; n < count; n += 1) {
      const repoCount = r.pick([1, 2, 2, 3, 3, 4, 4, 5, 6, 8]);
      const pool = ["a", "b", "c", "d", "e"].slice(0, r.int(1, 4));
      const repos = Array.from({ length: repoCount }, () =>
        POLICY_DEFINITIONS.map((): [string, string | null] => {
          const letter = r.pick(["L", "L", "L", "L", "I", "A", "A", "U"]);
          if (letter === "A" || letter === "U") return [letter, null];
          if (stratum === "empty_sha" && r.chance(0.25)) return [letter, r.pick(["", "", null])];
          return [letter, r.pick(pool)];
        }),
      );
      const perm = stratum === "shuffled_order" ? r.shuffle(POLICY_DEFINITIONS.map((_, k) => k)) : null;
      const input: Json = { repos, perm };
      const ts = capture(() => {
        const expanded = expandRepos(frozen(input) as Parameters<typeof expandRepos>[0]);
        const scores = scoreRepositories(expanded);
        return { repos: expanded.map((repo) => [repo.evidenceCoverage, repo.consistency]), scores };
      });
      out.push({ id: `score-${out.length}`, stratum, input, ts });
    }
  }
  return out;
}

// ---------------------------------------------------------------------------------------------
// classifyAgentSignal(repository, "", item) <-> classify_agent(item, repository)

const ASCII_LINES = [
  "fix: correct a typo", "feat(api): add rate capture", "chore(deps): bump zod", "Merge pull request #12 from x/y",
  "Co-authored-by: Claude <noreply@anthropic.com>", "co-authored-by: GitHub Copilot <copilot@github.com>",
  "Co-Authored-By: Cursor Agent <cursor@example.com>", "Co-authored-by: Jane Doe <jane@example.com>",
  "CURSOR_AGENT_PR_BODY", "co-authored-by: AI <ai@example.com>", "co-authored-by: mail <brain@example.com>",
  "Co-authored-by:\tAgent Smith <smith@example.com>", "co-authored-by:claude", "Signed-off-by: Dev <dev@example.com>",
  "co-authored-by: said <x@example.com>", "co-authored-by: openai-bot", "Co-authored-by: ai_helper",
  "docs: mention claude in the README", "co-authored-by: x", "CO-AUTHORED-BY: COPILOT",
];
const UNICODE_TAILS = [
  "ſomething curſor", "copılot", "éai", "aié", "éaié", "中ai", "aİ",
  "İA", "à ai", "aí", "Kai", "cláude", "­ ai", "AIß", "αai", "😀ai",
  "ΑI", "agenté", "éagent", "cıaude", "coрilot",
];
const PEOPLE: Json[] = [
  null, { login: "dev", type: "User" }, { login: "dependabot[bot]", type: "Bot" }, { login: "renovate", type: "Bot" },
  { login: "octo", type: "Organization" }, { login: "ci-user", type: "User" },
];

function classifyVectors(): Vector[] {
  const r = prng(SEED + 3);
  const out: Vector[] = [];
  const message = (lines: readonly string[]) =>
    Array.from({ length: r.int(1, 3) }, () => r.pick(lines)).join(r.pick(["\n", "\n\n", "\n"]));
  const baseItem = (msg: Json): JsonObject => {
    const sha = sha1(`classify-${out.length}`);
    const item: JsonObject = {
      sha,
      html_url: `https://github.com/${ORG}/r/commit/${sha}`,
      author: r.pick(PEOPLE),
      committer: r.pick(PEOPLE),
      commit: { message: msg },
    };
    const verification = r.pick<Json | undefined>([undefined, { verified: true }, { verified: false }, {}]);
    if (verification !== undefined) (item.commit as JsonObject).verification = verification;
    return item;
  };
  const push = (stratum: string, item: JsonObject) => {
    const input: Json = { repository: `${ORG}/r${out.length % 7}`, item };
    const ts = capture(() => {
      const frozenInput = frozen(input) as { repository: string; item: Parameters<typeof classifyAgentSignal>[2] };
      return classifyAgentSignal(frozenInput.repository, "", frozenInput.item);
    });
    out.push({ id: `classify-${out.length}`, stratum, input, ts });
  };
  for (let n = 0; n < 320; n += 1) push("in_domain", baseItem(message(ASCII_LINES)));
  for (let n = 0; n < 120; n += 1) {
    const tail = r.pick(UNICODE_TAILS);
    const line = `${r.pick(["co-authored-by: ", "Co-authored-by: x ", "CO-AUTHORED-BY:"])}${tail}`;
    push("unicode_regex", baseItem(r.chance(0.5) ? line : `${r.pick(ASCII_LINES)}\n\n${line}`));
  }
  const edges: Array<(item: JsonObject) => void> = [
    (item) => { delete (item.commit as JsonObject).message; },
    (item) => { (item.commit as JsonObject).message = null; },
    (item) => { (item.commit as JsonObject).message = ""; },
    (item) => { (item.commit as JsonObject).message = 42; },
    (item) => { delete item.commit; },
    (item) => { item.commit = null; },
    (item) => { delete item.sha; },
    (item) => { delete item.html_url; },
    (item) => { item.author = { login: "", type: "Bot" }; },
    (item) => { item.author = { type: "Bot" }; item.committer = { login: "fallback" }; },
    (item) => { item.author = { type: "Bot" }; item.committer = null; },
    (item) => { (item.commit as JsonObject).verification = { verified: null }; },
    (item) => { (item.commit as JsonObject).verification = null; },
    (item) => { item.author = { login: "bot", type: "bot" }; },
    (item) => { (item.commit as JsonObject).message = "\nco-authored-by: claude"; },
  ];
  for (let n = 0; n < 90; n += 1) {
    const item = baseItem(message(ASCII_LINES));
    edges[n % edges.length](item);
    push("edge_fields", item);
  }
  return out;
}

// ---------------------------------------------------------------------------------------------
// matchPolicyChanges <-> match_policy_changes

const POLICY_PATHS = POLICY_DEFINITIONS.flatMap((definition) => definition.candidates);
const NOISE_PATHS = [
  "src/app.ts", "README.md", "docs/index.md", "agents.md", ".github/workflows/README.md", "security.md",
  ".github/workflows/sub/nightly.yml", ".github/workflow/ci.yml", "github/workflows/ci.yml", ".github/workflows/ci.yml.bak",
  ".github/ISSUE_TEMPLATE/bug.yml", "LICENSE.rst", "docs/CODEOWNERS.md",
];
const WORKFLOW_NAMES = ["ci", "release", "codeql", "hf-sync", "hf_sync", "deploy", "lint", "pages", "nightly", "scorecard"];

function workflowPath(r: ReturnType<typeof prng>, style: "lower" | "mixed" | "unicode"): string {
  let name = r.pick(WORKFLOW_NAMES);
  if (style === "mixed") {
    name = r.pick([name.toUpperCase(), name[0].toUpperCase() + name.slice(1), name, `${name}-${r.pick(["A", "b", "_c", "-D"])}`]);
  } else if (style === "unicode") {
    name = r.pick([`é${name}`, `${name}ä`, `Å${name}`, `Δ${name}`, `Ａ${name}`, `😀${name}`, `${name}ß`, `z${name}`]);
  }
  const extensions = style === "lower" ? [".yml", ".yaml"] : [".yml", ".yaml", ".YML", ".Yaml"];
  return `.github/workflows/${name}${r.pick(extensions)}`;
}

function matchVectors(): Vector[] {
  const r = prng(SEED + 4);
  const out: Vector[] = [];
  const pathFor = (style: "lower" | "mixed" | "unicode") =>
    r.chance(0.35) ? workflowPath(r, style) : r.chance(0.6) ? r.pick(POLICY_PATHS) : r.pick(NOISE_PATHS);
  const push = (stratum: string, files: Json[]) => {
    const input: Json = { files };
    const ts = capture(() => matchPolicyChanges((frozen(input) as { files: Parameters<typeof matchPolicyChanges>[0] }).files));
    out.push({ id: `match-${out.length}`, stratum, input, ts });
  };
  const fileList = (style: "lower" | "mixed" | "unicode") =>
    Array.from({ length: r.int(0, 6) }, (): Json => {
      const file: JsonObject = { filename: pathFor(style) };
      if (r.chance(0.25)) file.previous_filename = pathFor(style);
      return file;
    });
  for (let n = 0; n < 250; n += 1) push("ascii_lower", fileList("lower"));
  for (let n = 0; n < 110; n += 1) push("mixed_case", fileList("mixed"));
  for (let n = 0; n < 90; n += 1) push("unicode", fileList("unicode"));
  const edgeFiles: Json[][] = [
    [{ filename: ".github/workflows/ci.yml\n" }],
    [{ filename: "SECURITY.md\n" }],
    [{ filename: 123 }],
    [{ filename: null }],
    [{ filename: "" }],
    [{ filename: true }],
    [{ filename: "README.md", previous_filename: 0 }],
    [{ filename: ".github/workflows/x.yaml", previous_filename: ".github/workflows/y.yml\n" }],
    [{}],
    [{ filename: ["SECURITY.md"] }],
  ];
  for (let n = 0; n < 70; n += 1) {
    const files = [...fileList("lower"), ...edgeFiles[n % edgeFiles.length]];
    push("edge_types", r.shuffle(files));
  }
  return out;
}

// ---------------------------------------------------------------------------------------------
// resolvePolicies <-> resolve_policies

type EntryInput = [string, string, string];
const expandEntries = (entries: EntryInput[] | null) =>
  entries === null ? null : entries.map(([path, type, sha]) => ({ path, type: type as "blob" | "tree" | "commit", sha, mode: "100644", url: "" }));
// Output row: [key, state, path, blobSha, sourceRepo] plus memberCount only when the observation carries it.
const policyRows = (policies: ReturnType<typeof resolvePolicies>) =>
  policies.map((policy) => {
    const row: unknown[] = [policy.key, policy.state, policy.path, policy.blobSha, policy.sourceRepo];
    if (policy.memberCount !== undefined) row.push(policy.memberCount);
    return row;
  });

function resolveVectors(): Vector[] {
  const r = prng(SEED + 5);
  const out: Vector[] = [];
  const entryList = (stratum: string): EntryInput[] => {
    const style = stratum === "mixed_case" ? "mixed" : stratum === "unicode" ? "unicode" : "lower";
    const entries: EntryInput[] = [];
    const seen = new Set<string>();
    for (let k = r.int(0, 10); k > 0; k -= 1) {
      let path = r.chance(0.4) ? workflowPath(r, style) : r.chance(0.6) ? r.pick(POLICY_PATHS) : r.pick(NOISE_PATHS);
      if (stratum === "trailing_newline" && r.chance(0.4)) path = `${path}\n`;
      if (seen.has(path)) continue;
      seen.add(path);
      entries.push([path, r.chance(0.92) ? "blob" : r.pick(["tree", "commit"]), sha1(`${stratum}-${out.length}-${k}`).slice(0, 8)]);
    }
    if (stratum === "duplicates" && entries.length) {
      for (let k = r.int(1, 3); k > 0; k -= 1) {
        const twin = r.pick(entries);
        entries.splice(r.int(0, entries.length), 0, [twin[0], twin[1], sha1(`dup-${out.length}-${k}`).slice(0, 8)]);
      }
    }
    return entries;
  };
  const plan: Array<[string, number]> = [["ascii_lower", 260], ["mixed_case", 100], ["unicode", 60], ["trailing_newline", 40], ["duplicates", 60]];
  for (const [stratum, count] of plan) {
    for (let n = 0; n < count; n += 1) {
      const input: Json = {
        entries: entryList(stratum),
        complete: r.chance(0.8),
        defaults: r.chance(0.6) ? entryList(stratum === "duplicates" ? "duplicates" : "ascii_lower") : null,
        defaultComplete: r.chance(0.8),
      };
      const ts = capture(() => {
        const args = frozen(input) as { entries: EntryInput[]; complete: boolean; defaults: EntryInput[] | null; defaultComplete: boolean };
        return policyRows(resolvePolicies(expandEntries(args.entries) ?? [], args.complete, expandEntries(args.defaults), args.defaultComplete, `${ORG}/.github`));
      });
      out.push({ id: `resolve-${out.length}`, stratum, input, ts });
    }
  }
  return out;
}

// ---------------------------------------------------------------------------------------------
// scanOrganization <-> scan_organization against a mocked GitHub described by a compact spec.
// Timestamps (startedAt/observedAt/completedAt) and limitation wording are projected out.

type CommitSpec = { message: string; bot: boolean; files: string[]; detail?: number; detailSha?: string; files100?: boolean };
// Omitted optional fields take the defaults applied in withDefaults (same rule on the Python side).
type RepoSpec = {
  name: string; full_name: string; branch?: string | null; archived?: boolean; disabled?: boolean; fork?: boolean; private?: boolean;
  protected?: boolean; head?: string; treeReply?: string; truncated?: boolean | string | null; entries?: Array<[string, string]>;
  community?: number | null; rules?: number | null; commits?: CommitSpec[] | number; branchStatus?: number; raw?: Json;
};
type FullRepoSpec = Required<Omit<RepoSpec, "head" | "treeReply" | "raw">> & Pick<RepoSpec, "head" | "treeReply" | "raw">;
const withDefaults = (spec: RepoSpec): FullRepoSpec => ({
  branch: "main", archived: false, disabled: false, fork: false, private: false, protected: false, truncated: false, entries: [],
  community: null, rules: null, commits: [], branchStatus: 200, ...spec,
});
// decrement: each response reports x-ratelimit-remaining one lower than the previous one, as GitHub does.
type ScanSpec = { sample: number; headers: Record<string, string>; decrement?: boolean; org: { status: number; login: string; name: string | null }; repos: RepoSpec[]; perturbation: string | null };

const headOf = (spec: FullRepoSpec) => spec.head ?? sha1(`${spec.full_name}/head`);
const treeOf = (spec: FullRepoSpec) => sha1(`${spec.full_name}/tree`);
const commitShaOf = (spec: FullRepoSpec, index: number) => sha1(`${spec.full_name}/commit/${index}`);

function inventoryItem(spec: FullRepoSpec): Json {
  if (spec.raw !== undefined) return spec.raw;
  return {
    name: spec.name, full_name: spec.full_name, description: null, default_branch: spec.branch,
    archived: spec.archived, disabled: spec.disabled, fork: spec.fork, private: spec.private, language: null,
    updated_at: "2026-11-01T00:00:00Z", html_url: `https://github.com/${spec.full_name}`,
  };
}

function route(scan: ScanSpec, path: string, page: number): { status: number; body: Json } {
  const notFound = { status: 404, body: { message: "Not Found" } };
  const lower = path.toLowerCase();
  if (lower === `/orgs/${ORG}`) {
    if (scan.org.status !== 200) return { status: scan.org.status, body: { message: "synthetic org failure" } };
    return { status: 200, body: { login: scan.org.login, name: scan.org.name, description: null, html_url: `https://github.com/${ORG}`, public_repos: scan.repos.length } };
  }
  if (lower === `/orgs/${ORG}/repos`) return { status: 200, body: scan.repos.slice((page - 1) * 100, page * 100).map((item) => inventoryItem(withDefaults(item))) };
  const match = /^\/repos\/([^/]+\/[^/]+)\/(.+)$/.exec(path);
  if (!match) return notFound;
  const found = scan.repos.find((item) => item.raw === undefined && item.full_name === match[1]);
  if (!found) return notFound;
  const spec = withDefaults(found);
  const rest = match[2];
  if (rest.startsWith("branches/")) {
    if (spec.branchStatus !== 200) return { status: spec.branchStatus, body: { message: "synthetic branch failure" } };
    return { status: 200, body: { name: spec.branch, protected: spec.protected, commit: { sha: headOf(spec), commit: { tree: { sha: treeOf(spec) } } } } };
  }
  if (rest.startsWith("git/trees/")) {
    const body: JsonObject = { sha: spec.treeReply ?? treeOf(spec), tree: spec.entries.map(([entryPath, sha]) => ({ path: entryPath, mode: "100644", type: "blob", sha, url: "" })) };
    if (spec.truncated !== null) body.truncated = spec.truncated;
    return { status: 200, body };
  }
  if (rest === "community/profile") return spec.community === null ? notFound : { status: 200, body: { health_percentage: spec.community } };
  if (rest.startsWith("rules/branches/")) return spec.rules === null ? notFound : { status: 200, body: Array.from({ length: spec.rules }, () => ({ type: "deletion" })) };
  if (rest === "commits") {
    if (typeof spec.commits === "number") return { status: spec.commits, body: { message: "synthetic history failure" } };
    return {
      status: 200,
      body: spec.commits.map((commit, index) => {
        const sha = commitShaOf(spec, index);
        const person = commit.bot ? { login: "dependabot[bot]", type: "Bot" } : { login: "dev", type: "User" };
        return { sha, html_url: `https://github.com/${spec.full_name}/commit/${sha}`, author: person, committer: person, commit: { message: commit.message, verification: { verified: true } } };
      }),
    };
  }
  if (rest.startsWith("commits/") && Array.isArray(spec.commits)) {
    const index = spec.commits.findIndex((_, k) => commitShaOf(spec, k) === rest.slice("commits/".length));
    if (index < 0) return notFound;
    const commit = spec.commits[index];
    if (commit.detail && commit.detail !== 200) return { status: commit.detail, body: { message: "synthetic detail failure" } };
    const files = commit.files100 ? Array.from({ length: 100 }, (_, k) => ({ filename: `src/f${k}.ts` })) : commit.files.map((filename) => ({ filename }));
    return { status: 200, body: { sha: commit.detailSha ?? commitShaOf(spec, index), files } };
  }
  return notFound;
}

// Compact projection shared with backend/tests/test_parity.py (SCAN_* indexes there).
// repo row: [fullName, defaultBranch, headSha, treeSha, treeComplete, protected, communityHealth, rulesCount,
//            workflowCount, evidenceCoverage, consistency, hasError, policies, signals, history]
// policy row: [state, path, blobSha, sourceRepo, memberCount|null] in POLICY_DEFINITIONS order, except that a row
//             whose path, blobSha and sourceRepo are all null is written as state + memberCount ("ABSENT", "UNKNOWN0")
// signal row: [classification, commitSha, path, changedPaths, policyKeys, actor, verified, sourceHeadSha === headSha]
// head, tree and commit SHAs are cut to their first 12 hex digits (the mock derives them from sha1 of fixed text).
const short = (sha: string | null) => (typeof sha === "string" ? sha.slice(0, 12) : sha);
const policyCell = (policy: { state: string; path: string | null; blobSha: string | null; sourceRepo: string | null; memberCount?: number }) =>
  policy.path === null && policy.blobSha === null && policy.sourceRepo === null
    ? `${policy.state}${policy.memberCount ?? ""}`
    : [policy.state, policy.path, policy.blobSha, policy.sourceRepo, policy.memberCount ?? null];
function project(result: Awaited<ReturnType<typeof scanOrganization>>): Json {
  return wire({
    mode: result.mode,
    org: [result.org.login, result.org.name, result.org.publicRepos],
    inventory: [result.inventory.publicRepos, result.inventory.active, result.inventory.archived, result.inventory.forks],
    sampleSize: result.sampleSize,
    publicInventory: result.publicInventory ? result.publicInventory.map((item) => [item.fullName, item.archived, item.fork, item.disabled]) : null,
    scores: [result.scores.alignment, result.scores.consistency, result.scores.evidenceCoverage],
    rate: [result.rate.limit, result.rate.remaining, result.rate.resetAt],
    sourceUrls: result.sourceUrls,
    limitationsCount: result.limitations.length,
    repositories: result.repositories.map((repo) => [
      repo.fullName, repo.defaultBranch, short(repo.headSha), short(repo.treeSha), repo.treeComplete, repo.protected, repo.communityHealth,
      repo.rulesCount, repo.workflowCount, repo.evidenceCoverage, repo.consistency, repo.error !== undefined,
      repo.policies.map(policyCell),
      repo.agentSignals.map((signal) => [signal.classification, short(signal.commitSha), signal.path, signal.changedPaths ?? null, signal.policyKeys ?? null, signal.actor, signal.verified, signal.sourceHeadSha === repo.headSha]),
      repo.policyHistory
        ? [repo.policyHistory.status, repo.policyHistory.commitsExamined, repo.policyHistory.attributedCandidates, repo.policyHistory.detailsExamined, repo.policyHistory.unexaminedCandidates, repo.policyHistory.fileListsTruncated, repo.policyHistory.error !== undefined]
        : null,
    ]),
  });
}

const POOL = ["alpha", "beta", "gamma", "delta", "epsilon", "zeta", "eta", "theta"];
const RATE_PERTURBATIONS: Array<[string, (headers: Record<string, string>) => void]> = [
  ["reset_missing", (h) => { delete h["x-ratelimit-reset"]; }],
  ["reset_empty", (h) => { h["x-ratelimit-reset"] = ""; }],
  ["reset_nan", (h) => { h["x-ratelimit-reset"] = "soon"; }],
  ["reset_fraction", (h) => { h["x-ratelimit-reset"] = "1792289000.5"; }],
  ["reset_year_10000", (h) => { h["x-ratelimit-reset"] = "253402300800"; }],
  ["reset_negative", (h) => { h["x-ratelimit-reset"] = "-1"; }],
  ["limit_zero", (h) => { h["x-ratelimit-limit"] = "0"; }],
  ["limit_underscore", (h) => { h["x-ratelimit-limit"] = "5_000"; }],
  ["remaining_word", (h) => { h["x-ratelimit-remaining"] = "many"; }],
  ["remaining_fraction", (h) => { h["x-ratelimit-remaining"] = "4.5"; }],
];
const STRICT_PERTURBATIONS = [
  "private_repo", "foreign_repo", "login_case", "login_foreign", "org_name_null", "org_name_empty", "tree_sha_mismatch",
  "head_sha_short", "detail_sha_mismatch", "truncated_missing", "truncated_string", "branch_special", "default_branch_null",
  "non_object_inventory_item", "duplicate_name_case",
];

function scanVectors(): Promise<Vector[]> {
  const r = prng(SEED + 6);
  const commitMessages = ["fix: typo", "Co-authored-by: Claude <noreply@anthropic.com>", "chore: bump", "CURSOR_AGENT_PR_BODY", "docs: update"];
  const repoSpec = (index: number, workflowStyle: "lower" | "mixed"): RepoSpec => {
    const name = index === 0 && r.chance(0.75) ? ".github" : `${r.pick(POOL)}-${index}`;
    const full_name = `${ORG}/${name}`;
    const entries: Array<[string, string]> = [];
    const seen = new Set<string>();
    for (let k = r.pick([0, 1, 2, 3, 4, 6]); k > 0; k -= 1) {
      const path = r.chance(0.45) ? workflowPath(r, workflowStyle) : r.pick(POLICY_PATHS);
      if (seen.has(path)) continue;
      seen.add(path);
      entries.push([path, r.pick(["a1", "b2", "c3", "d4"])]);
    }
    const commits: CommitSpec[] = Array.from({ length: r.pick([0, 0, 1, 2, 3]) }, () => ({
      message: r.pick(commitMessages),
      bot: r.chance(0.4),
      files: Array.from({ length: r.int(0, 3) }, () => (r.chance(0.5) ? r.pick(POLICY_PATHS) : workflowPath(r, "lower"))),
    }));
    const full: FullRepoSpec = withDefaults({
      name, full_name, branch: r.pick(["main", "main", "master"]), archived: r.chance(0.1), disabled: r.chance(0.03), fork: r.chance(0.06),
      protected: r.chance(0.5), entries, community: r.chance(0.7) ? r.int(0, 100) : null, rules: r.chance(0.5) ? r.int(0, 3) : null, commits,
    });
    // Store only the fields that differ from withDefaults, to keep the committed vectors small.
    const defaults = withDefaults({ name, full_name }) as Record<string, unknown>;
    const spec: Record<string, unknown> = { name, full_name };
    for (const [key, value] of Object.entries(full)) {
      if (key !== "name" && key !== "full_name" && JSON.stringify(value) !== JSON.stringify(defaults[key])) spec[key] = value;
    }
    return spec as RepoSpec;
  };
  const scenario = (stratum: string, index: number): ScanSpec => {
    const workflowStyle = stratum === "mixed_case_workflows" ? "mixed" : "lower";
    const repos = Array.from({ length: r.pick([1, 2, 2, 3, 3, 4, 4, 5, 6, 8]) }, (_, k) => repoSpec(k, workflowStyle));
    const headers: Record<string, string> = {
      "x-ratelimit-limit": "5000", "x-ratelimit-remaining": String(r.int(4000, 4999)), "x-ratelimit-reset": String(1792289000 + r.int(0, 3600)),
    };
    const scan: ScanSpec = { sample: r.pick([4, 6, 8]), headers, org: { status: 200, login: ORG, name: "SZL Holdings" }, repos, perturbation: null };
    if (stratum === "no_rate_headers") scan.headers = {};
    if (stratum === "low_budget") headers["x-ratelimit-remaining"] = String(r.int(0, 40));
    if ((stratum === "baseline" || stratum === "low_budget") && r.chance(0.5)) scan.decrement = true;
    if (stratum === "low_budget" && scan.decrement) scan.perturbation = "budget_decrement";
    if (stratum === "failures") {
      for (const spec of repos) {
        if (!r.chance(0.5)) continue;
        const which = r.pick(["branch", "tree", "community", "rules", "commits", "detail", "detail100"]);
        if (which === "branch") spec.branchStatus = r.pick([403, 404, 503]);
        else if (which === "tree") spec.truncated = true;
        else if (which === "community") spec.community = null;
        else if (which === "rules") spec.rules = null;
        else if (which === "commits") spec.commits = r.pick([404, 503]);
        else if (Array.isArray(spec.commits) && spec.commits.length) {
          spec.commits[0].bot = true;
          if (which === "detail") spec.commits[0].detail = r.pick([403, 503]);
          else spec.commits[0].files100 = true;
        }
      }
    }
    if (stratum === "rate_headers") {
      const [name, apply] = RATE_PERTURBATIONS[index % RATE_PERTURBATIONS.length];
      apply(headers);
      scan.perturbation = name;
    }
    if (stratum === "edge_strict") {
      const name = STRICT_PERTURBATIONS[index % STRICT_PERTURBATIONS.length];
      scan.perturbation = name;
      const target = repos[repos.length - 1];
      if (name === "private_repo") target.private = true;
      else if (name === "foreign_repo") target.full_name = `other-org/${target.name}`;
      else if (name === "login_case") scan.org.login = "SZL-Holdings";
      else if (name === "login_foreign") scan.org.login = "other-org";
      else if (name === "org_name_null") scan.org.name = null;
      else if (name === "org_name_empty") scan.org.name = "";
      else if (name === "tree_sha_mismatch") target.treeReply = sha1("elsewhere");
      else if (name === "head_sha_short") target.head = "abc123";
      else if (name === "detail_sha_mismatch") {
        target.commits = [{ message: "CURSOR_AGENT_PR_BODY", bot: true, files: ["SECURITY.md"], detailSha: sha1("other") }];
      } else if (name === "truncated_missing") target.truncated = null;
      else if (name === "truncated_string") target.truncated = "false";
      else if (name === "branch_special") target.branch = "feat(x)/y z";
      else if (name === "default_branch_null") target.branch = null;
      else if (name === "non_object_inventory_item") repos.push({ ...repoSpec(repos.length, "lower"), raw: "not-a-repository" });
      else if (name === "duplicate_name_case") repos.push({ ...target, full_name: target.full_name.toUpperCase(), name: target.name.toUpperCase() });
    }
    return scan;
  };
  Object.defineProperty(globalThis, "window", { value: globalThis, configurable: true });
  const originalFetch = globalThis.fetch;
  const plan: Array<[string, number]> = [
    ["baseline", 190], ["no_rate_headers", 80], ["mixed_case_workflows", 70], ["failures", 70], ["low_budget", 30], ["rate_headers", 40], ["edge_strict", 45],
  ];
  const run = async () => {
    const out: Vector[] = [];
    try {
      for (const [stratum, count] of plan) {
        for (let n = 0; n < count; n += 1) {
          const input = scenario(stratum, n) as unknown as Json;
          const scan = frozen(input) as ScanSpec;
          let served = 0;
          globalThis.fetch = async (request) => {
            const url = new URL(String(request));
            const reply = route(scan, decodeURIComponent(url.pathname), Number(url.searchParams.get("page") ?? "1"));
            const headers = { ...scan.headers };
            if (scan.decrement) headers["x-ratelimit-remaining"] = String(Number(headers["x-ratelimit-remaining"]) - served);
            served += 1;
            return new Response(JSON.stringify(reply.body), { status: reply.status, headers });
          };
          let ts: Json;
          try {
            ts = project(await scanOrganization(ORG, scan.sample, () => {}, () => {}));
          } catch (error) {
            ts = errorOf(error);
          }
          out.push({ id: `scan-${out.length}`, stratum, input, ts });
        }
      }
    } finally {
      globalThis.fetch = originalFetch;
      Reflect.deleteProperty(globalThis, "window");
    }
    return out;
  };
  return run();
}

// ---------------------------------------------------------------------------------------------

// POLICY_DEFINITIONS travel in every file header so the Python side can check labels, weights,
// candidates and set prefixes (the compact output rows above leave them out).
const DEFINITIONS = POLICY_DEFINITIONS.map((definition) => [
  definition.key, definition.label, definition.weight, definition.inheritable, definition.candidates, definition.setPrefix ?? null,
]);

function render(name: string, source: string, vectors: Vector[]): string {
  const strata: Record<string, number> = {};
  for (const vector of vectors) strata[vector.stratum] = (strata[vector.stratum] ?? 0) + 1;
  const header = JSON.stringify({ schema: SCHEMA, function: name, ts: source, seed: SEED, count: vectors.length, strata, definitions: DEFINITIONS });
  return `${header.slice(0, -1)},"vectors":[\n${vectors.map((vector) => JSON.stringify(vector)).join(",\n")}\n]}\n`;
}

async function main() {
  const check = process.argv.includes("--check");
  const files: Array<[string, string, Vector[]]> = [
    ["js_round", "lib/audit.ts Math.round (score rounding)", jsRoundVectors()],
    ["score_repositories", "lib/audit.ts scoreRepositories", scoreVectors()],
    ["classify_agent", "lib/audit.ts classifyAgentSignal", classifyVectors()],
    ["match_policy_changes", "lib/audit.ts matchPolicyChanges", matchVectors()],
    ["resolve_policies", "lib/audit.ts resolvePolicies", resolveVectors()],
    ["scan_organization", "lib/audit.ts scanOrganization (mocked GitHub)", await scanVectors()],
  ];
  mkdirSync(VECTOR_DIR, { recursive: true });
  let stale = 0;
  for (const [name, source, vectors] of files) {
    const text = render(name, source, vectors);
    const path = join(VECTOR_DIR, `${name}.json`);
    if (check) {
      let committed: string | null = null;
      try {
        committed = readFileSync(path, "utf8").replace(/\r\n/g, "\n");
      } catch {
        committed = null;
      }
      if (committed !== text) {
        stale += 1;
        console.error(`STALE ${path}: regenerate with node --experimental-strip-types tests/parity/generate.mts`);
      } else {
        console.log(`OK ${name} ${vectors.length} vectors`);
      }
    } else {
      writeFileSync(path, text);
      console.log(`wrote ${name} ${vectors.length} vectors ${Buffer.byteLength(text)} bytes`);
    }
  }
  if (stale) process.exit(1);
}

await main();
