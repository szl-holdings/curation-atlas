import { POLICY_DEFINITIONS, canonicalize, type AuditResult, type EvidenceMode, type PolicyState } from "./audit.ts";

type RecordedPolicy = {
  key: string;
  state: PolicyState;
  path: string | null;
  sourceRepo: string | null;
  blobSha: string | null;
  memberCount?: number;
};
type RecordedRepo = {
  fullName: string;
  headSha: string | null;
  treeSha: string | null;
  treeComplete: boolean;
  error?: string;
  policies: RecordedPolicy[];
};
export type ComparisonAudit = {
  mode: EvidenceMode;
  orgLogin: string;
  observedAt: string;
  repositories: RecordedRepo[];
};
export type VerifiedBaseline = { audit: ComparisonAudit; receiptSha256: string };
export type PolicyDelta = {
  fullName: string;
  key: string;
  label: string;
  change: "ADDED" | "REMOVED" | "CHANGED" | "UNCHANGED" | "UNKNOWN";
  before: RecordedPolicy;
  after: RecordedPolicy;
  reason: string;
};
export type AuditComparison = {
  overlapCount: number;
  changedRevisionCount: number;
  enteredCohort: string[];
  leftCohort: string[];
  deltas: PolicyDelta[];
};

function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("The receipt contains an invalid object.");
  return value as Record<string, unknown>;
}
function text(value: unknown, max = 500): string {
  if (typeof value !== "string" || value.length > max) throw new Error("The receipt contains an invalid or oversized field.");
  return value;
}
function nullableText(value: unknown, max = 500): string | null {
  return value === null ? null : text(value, max);
}
function timestamp(value: unknown): string {
  const result = text(value, 40);
  if (!/^\d{4}-\d{2}-\d{2}T/.test(result) || !Number.isFinite(Date.parse(result))) throw new Error("The receipt has an invalid observation time.");
  return result;
}
function boundedTree(value: unknown, depth = 0): void {
  if (depth > 48) throw new Error("The receipt nesting exceeds the supported limit.");
  if (value && typeof value === "object") {
    for (const child of Object.values(value)) boundedTree(child, depth + 1);
  }
}

export function projectComparisonAudit(value: unknown): ComparisonAudit {
  const audit = object(value);
  if (audit.schemaVersion !== 1 || audit.publicOnly !== true) throw new Error("Only public Curation Atlas v1 audits are supported.");
  if (!["MEASURED", "SAMPLE", "BLOCKED", "UNAVAILABLE"].includes(String(audit.mode))) throw new Error("The receipt has an unsupported evidence class.");
  const orgLogin = text(object(audit.org).login, 39).toLowerCase();
  if (!/^[a-z\d](?:[a-z\d-]{0,37}[a-z\d])?$/i.test(orgLogin)) throw new Error("The receipt has an invalid organization.");
  if (!Array.isArray(audit.repositories) || audit.repositories.length > 1000) throw new Error("The receipt has an invalid repository list.");
  const seen = new Set<string>();
  const repositories = audit.repositories.map((value): RecordedRepo => {
    const repository = object(value);
    const fullName = text(repository.fullName, 150).toLowerCase();
    if (!fullName.startsWith(orgLogin + "/") || !/^[a-z\d-]+\/[a-z\d_.-]+$/i.test(fullName)) throw new Error("A receipt repository does not belong to its organization.");
    if (seen.has(fullName)) throw new Error("The receipt repeats a repository identity.");
    seen.add(fullName);
    if (typeof repository.treeComplete !== "boolean") throw new Error("The receipt is missing its tree coverage state.");
    if (!Array.isArray(repository.policies) || repository.policies.length !== POLICY_DEFINITIONS.length) throw new Error("The receipt has an incomplete policy schema.");
    const policyKeys = new Set<string>();
    const policies = repository.policies.map((value): RecordedPolicy => {
      const policy = object(value);
      const key = text(policy.key, 40);
      if (!POLICY_DEFINITIONS.some((definition) => definition.key === key) || policyKeys.has(key)) throw new Error("The receipt has an unknown or repeated policy key.");
      policyKeys.add(key);
      if (!["LOCAL", "INHERITED", "ABSENT", "UNKNOWN"].includes(String(policy.state))) throw new Error("The receipt has an invalid policy state.");
      if (policy.memberCount !== undefined && (!Number.isInteger(policy.memberCount) || Number(policy.memberCount) < 0)) throw new Error("The receipt has an invalid file count.");
      return {
        key,
        state: policy.state as PolicyState,
        path: nullableText(policy.path),
        sourceRepo: nullableText(policy.sourceRepo, 150)?.toLowerCase() ?? null,
        blobSha: nullableText(policy.blobSha, 1_500_000),
        ...(key === "workflows" && policy.memberCount !== undefined ? { memberCount: Number(policy.memberCount) } : {}),
      };
    });
    return {
      fullName,
      headSha: nullableText(repository.headSha, 40)?.toLowerCase() ?? null,
      treeSha: nullableText(repository.treeSha, 40)?.toLowerCase() ?? null,
      treeComplete: repository.treeComplete,
      ...(repository.error !== undefined ? { error: text(repository.error, 2000) } : {}),
      policies,
    };
  });
  return { mode: audit.mode as EvidenceMode, orgLogin, observedAt: timestamp(audit.observedAt), repositories };
}

export async function verifyImportedReceipt(source: string): Promise<VerifiedBaseline> {
  if (new TextEncoder().encode(source).length > 2_000_000) throw new Error("Choose a Curation Atlas JSON receipt smaller than 2 MB.");
  const envelope = object(JSON.parse(source));
  boundedTree(envelope);
  if (envelope.receiptSchema !== "curation-atlas/1") throw new Error("This file is not a Curation Atlas v1 receipt.");
  const expected = text(envelope.receiptSha256, 64).toLowerCase();
  if (!/^[a-f\d]{64}$/.test(expected)) throw new Error("The receipt digest is invalid.");
  const payload = { ...envelope };
  delete payload.receiptSha256;
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonicalize(payload)));
  const actual = [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
  if (actual !== expected) throw new Error("The receipt digest does not match its contents. No baseline was loaded.");
  return { audit: projectComparisonAudit(envelope.audit), receiptSha256: actual };
}

function pinned(repository: RecordedRepo): boolean {
  return !repository.error && repository.treeComplete && /^[a-f\d]{40}$/i.test(repository.headSha ?? "") && /^[a-f\d]{40}$/i.test(repository.treeSha ?? "");
}
function comparable(audit: ComparisonAudit, repository: RecordedRepo, policy: RecordedPolicy): boolean {
  if (audit.mode === "SAMPLE" || audit.mode === "UNAVAILABLE" || !pinned(repository) || policy.state === "UNKNOWN") return false;
  const definition = POLICY_DEFINITIONS.find((definition) => definition.key === policy.key)!;
  if (policy.state === "ABSENT") return policy.path === null && policy.blobSha === null && policy.sourceRepo === null && (policy.memberCount === undefined || policy.memberCount === 0);
  if (!policy.path || !policy.blobSha) return false;
  if (definition.setPrefix) {
    if (policy.path !== definition.setPrefix + "*" || !policy.blobSha.startsWith("set:")) return false;
    const members = policy.blobSha.slice(4).split("|");
    const names = new Set<string>();
    if (members.length !== policy.memberCount) return false;
    for (const member of members) {
      const colon = member.lastIndexOf(":");
      const path = member.slice(0, colon);
      if (colon < 0 || !path.startsWith(definition.setPrefix) || !/\.ya?ml$/i.test(path) || !/^[a-f\d]{40}$/i.test(member.slice(colon + 1)) || names.has(path)) return false;
      names.add(path);
    }
  } else if (!definition.candidates.includes(policy.path) || !/^[a-f\d]{40}$/i.test(policy.blobSha)) return false;
  if (policy.state === "INHERITED") {
    const origin = audit.repositories.find((candidate) => candidate.fullName === policy.sourceRepo);
    const originPolicy = origin?.policies.find((candidate) => candidate.key === policy.key);
    return definition.inheritable && policy.sourceRepo === audit.orgLogin + "/.github" && Boolean(origin && pinned(origin) && originPolicy?.state === "LOCAL" && originPolicy.path === policy.path && originPolicy.blobSha === policy.blobSha && originPolicy.sourceRepo === null);
  }
  return policy.sourceRepo === null;
}

export function compareAudits(previous: ComparisonAudit, currentValue: AuditResult): AuditComparison {
  const current = projectComparisonAudit(currentValue);
  if (previous.orgLogin !== current.orgLogin) throw new Error("Run an audit for the same organization as the loaded receipt.");
  if (Date.parse(previous.observedAt) > Date.parse(current.observedAt)) throw new Error("The loaded receipt is newer than the displayed audit. Run a fresh scan before comparing.");
  const before = new Map(previous.repositories.map((repository) => [repository.fullName, repository]));
  const after = new Map(current.repositories.map((repository) => [repository.fullName, repository]));
  const overlap = current.repositories.filter((repository) => before.has(repository.fullName));
  const deltas: PolicyDelta[] = [];
  let changedRevisionCount = 0;
  for (const repository of overlap) {
    const old = before.get(repository.fullName)!;
    if (previous.mode !== "SAMPLE" && previous.mode !== "UNAVAILABLE" && current.mode !== "SAMPLE" && current.mode !== "UNAVAILABLE" && pinned(old) && pinned(repository) && old.headSha !== repository.headSha) changedRevisionCount += 1;
    for (const definition of POLICY_DEFINITIONS) {
      const first = old.policies.find((policy) => policy.key === definition.key)!;
      const next = repository.policies.find((policy) => policy.key === definition.key)!;
      let change: PolicyDelta["change"] = "UNKNOWN";
      let reason = "Both observations need full source bindings and known policy evidence.";
      if (comparable(previous, old, first) && comparable(current, repository, next)) {
        if (first.state === "ABSENT" && next.state !== "ABSENT") { change = "ADDED"; reason = "An effective policy is present in the later complete observation."; }
        else if (first.state !== "ABSENT" && next.state === "ABSENT") { change = "REMOVED"; reason = "The later complete observation records no effective policy."; }
        else if (canonicalize({ ...first, memberCount: first.state === "ABSENT" ? undefined : first.memberCount }) === canonicalize({ ...next, memberCount: next.state === "ABSENT" ? undefined : next.memberCount })) { change = "UNCHANGED"; reason = "The observed state, location, inheritance, and fingerprint match."; }
        else { change = "CHANGED"; reason = first.blobSha !== next.blobSha ? "The observed content or workflow-set fingerprint differs." : "The policy location or inheritance changed while the observed fingerprint matches."; }
      }
      deltas.push({ fullName: repository.fullName, key: definition.key, label: definition.label, change, before: first, after: next, reason });
    }
  }
  return {
    overlapCount: overlap.length,
    changedRevisionCount,
    enteredCohort: current.repositories.filter((repository) => !before.has(repository.fullName)).map((repository) => repository.fullName),
    leftCohort: previous.repositories.filter((repository) => !after.has(repository.fullName)).map((repository) => repository.fullName),
    deltas,
  };
}
