export type EvidenceMode = "MEASURED" | "SAMPLE" | "UNAVAILABLE" | "BLOCKED";
export type PolicyState = "LOCAL" | "INHERITED" | "ABSENT" | "UNKNOWN";
export type AgentClassification =
  | "AGENT_ASSISTANCE_DECLARED"
  | "AUTOMATION_ACTOR_OBSERVED"
  | "ATTRIBUTION_UNKNOWN";

export type RateState = {
  limit: number | null;
  remaining: number | null;
  resetAt: string | null;
};

export type PolicyDefinition = {
  key: string;
  label: string;
  weight: number;
  inheritable: boolean;
  candidates: string[];
  setPrefix?: string;
};

export type PolicyObservation = {
  key: string;
  label: string;
  weight: number;
  state: PolicyState;
  path: string | null;
  blobSha: string | null;
  sourceRepo: string | null;
  memberCount?: number;
};

export type AgentSignal = {
  classification: AgentClassification;
  repository: string;
  path: string;
  commitSha: string;
  message: string;
  actor: string;
  verified: boolean | null;
  url: string;
  evidence: string;
  sourceHeadSha?: string;
  changedPaths?: string[];
  policyKeys?: string[];
};

export type PolicyHistory = {
  sourceHeadSha: string;
  status: "MEASURED" | "BLOCKED";
  commitsExamined: number;
  attributedCandidates: number;
  detailsExamined: number;
  unexaminedCandidates: number;
  fileListsTruncated: boolean;
  error?: string;
};

export type RepoAudit = {
  name: string;
  fullName: string;
  description: string | null;
  defaultBranch: string;
  headSha: string | null;
  treeSha: string | null;
  treeComplete: boolean;
  protected: boolean | null;
  archived: boolean;
  language: string | null;
  updatedAt: string;
  communityHealth: number | null;
  rulesCount: number | null;
  workflowCount: number;
  policies: PolicyObservation[];
  consistency: number | null;
  evidenceCoverage: number;
  agentSignals: AgentSignal[];
  policyHistory?: PolicyHistory;
  error?: string;
};

export type AuditResult = {
  schemaVersion: 1;
  mode: EvidenceMode;
  publicOnly: true;
  org: {
    login: string;
    name: string;
    description: string | null;
    htmlUrl: string;
    publicRepos: number;
  };
  observedAt: string;
  startedAt: string;
  completedAt: string;
  inventory: {
    publicRepos: number;
    active: number;
    archived: number;
    forks: number;
  };
  sampleSize: number;
  publicInventory?: Array<{ fullName: string; archived: boolean; fork: boolean; disabled: boolean }>;
  repositories: RepoAudit[];
  scores: {
    alignment: null;
    consistency: number | null;
    evidenceCoverage: number;
  };
  rate: RateState;
  sourceUrls: string[];
  limitations: string[];
};

export const POLICY_DEFINITIONS: PolicyDefinition[] = [
  {
    key: "agent-instructions",
    label: "Agent instructions",
    weight: 4,
    inheritable: false,
    candidates: ["AGENTS.md", ".github/copilot-instructions.md", "CLAUDE.md", "GEMINI.md"],
  },
  {
    key: "codeowners",
    label: "Code ownership",
    weight: 5,
    inheritable: false,
    candidates: [".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"],
  },
  {
    key: "security",
    label: "Security policy",
    weight: 5,
    inheritable: true,
    candidates: [".github/SECURITY.md", "SECURITY.md", "docs/SECURITY.md"],
  },
  {
    key: "contributing",
    label: "Contributing guide",
    weight: 3,
    inheritable: true,
    candidates: [".github/CONTRIBUTING.md", "CONTRIBUTING.md", "docs/CONTRIBUTING.md"],
  },
  {
    key: "code-of-conduct",
    label: "Code of conduct",
    weight: 3,
    inheritable: true,
    candidates: [".github/CODE_OF_CONDUCT.md", "CODE_OF_CONDUCT.md", "docs/CODE_OF_CONDUCT.md"],
  },
  {
    key: "support",
    label: "Support policy",
    weight: 2,
    inheritable: true,
    candidates: [".github/SUPPORT.md", "SUPPORT.md", "docs/SUPPORT.md"],
  },
  {
    key: "governance",
    label: "Governance",
    weight: 4,
    inheritable: false,
    candidates: ["GOVERNANCE.md", ".github/GOVERNANCE.md", "docs/GOVERNANCE.md"],
  },
  {
    key: "license",
    label: "License",
    weight: 5,
    inheritable: false,
    candidates: ["LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING"],
  },
  {
    key: "dependabot",
    label: "Dependency updates",
    weight: 4,
    inheritable: false,
    candidates: [".github/dependabot.yml", ".github/dependabot.yaml"],
  },
  {
    key: "workflows",
    label: "Actions workflows",
    weight: 5,
    inheritable: false,
    candidates: [],
    setPrefix: ".github/workflows/",
  },
];

type TreeEntry = {
  path: string;
  mode: string;
  type: "blob" | "tree" | "commit";
  sha: string;
  size?: number;
  url: string;
};

type RepoApi = {
  name: string;
  full_name: string;
  description: string | null;
  default_branch: string;
  archived: boolean;
  disabled: boolean;
  fork: boolean;
  language: string | null;
  updated_at: string;
  html_url: string;
};

type RepoBuild = RepoAudit & { entries: TreeEntry[] };

const SNAPSHOT_AT = "2026-09-19T22:30:07Z";
const UNKNOWN_RATE: RateState = { limit: null, remaining: null, resetAt: null };

const snapshotPolicy = (
  key: string,
  state: PolicyState,
  path: string | null,
  blobSha: string | null,
  sourceRepo: string | null = null,
  memberCount?: number,
): PolicyObservation => {
  const definition = POLICY_DEFINITIONS.find((item) => item.key === key)!;
  return { key, label: definition.label, weight: definition.weight, state, path, blobSha, sourceRepo, memberCount };
};

function fillSnapshotPolicies(items: PolicyObservation[]): PolicyObservation[] {
  return POLICY_DEFINITIONS.map((definition) =>
    items.find((item) => item.key === definition.key) ??
      snapshotPolicy(definition.key, "UNKNOWN", null, null),
  );
}

const snapshotRepos: RepoAudit[] = [
  {
    name: ".github",
    fullName: "szl-holdings/.github",
    description: "Organization policy defaults",
    defaultBranch: "main",
    headSha: "0af851c120b0",
    treeSha: null,
    treeComplete: false,
    protected: null,
    archived: false,
    language: null,
    updatedAt: SNAPSHOT_AT,
    communityHealth: 100,
    rulesCount: null,
    workflowCount: 127,
    policies: fillSnapshotPolicies([
      snapshotPolicy("agent-instructions", "LOCAL", "AGENTS.md", null),
      snapshotPolicy("codeowners", "LOCAL", ".github/CODEOWNERS", "7b316c63d4e12f5c1abb13e5c57c45c8ad224399"),
      snapshotPolicy("security", "LOCAL", "SECURITY.md", null),
      snapshotPolicy("contributing", "LOCAL", "CONTRIBUTING.md", null),
      snapshotPolicy("code-of-conduct", "LOCAL", ".github/CODE_OF_CONDUCT.md", "415a0a14aebe0102d5db82dcc51dde5db16619f0"),
      snapshotPolicy("support", "LOCAL", "SUPPORT.md", null),
      snapshotPolicy("license", "LOCAL", "LICENSE", "d645695673349e3947e8e5ae42332d0ac3164cd7"),
      snapshotPolicy("workflows", "LOCAL", ".github/workflows/*", null, null, 127),
    ]),
    consistency: null,
    evidenceCoverage: 0,
    agentSignals: [
      {
        classification: "AGENT_ASSISTANCE_DECLARED",
        repository: "szl-holdings/.github",
        path: "AGENTS.md",
        commitSha: "1f4df1f2b2636efd097854409c32c15b3e9dd0ab",
        message: "Introduce AGENTS.md",
        actor: "Cursor Agent (declared co-author)",
        verified: true,
        url: "https://github.com/szl-holdings/.github/commit/1f4df1f2b2636efd097854409c32c15b3e9dd0ab",
        evidence: "Commit message contains CURSOR_AGENT_PR_BODY markers and a Cursor Agent co-author trailer.",
      },
    ],
  },
  {
    name: "a11oy",
    fullName: "szl-holdings/a11oy",
    description: "Governed AI product surface",
    defaultBranch: "main",
    headSha: "a2244bde2a79",
    treeSha: null,
    treeComplete: false,
    protected: true,
    archived: false,
    language: "Python",
    updatedAt: SNAPSHOT_AT,
    communityHealth: 100,
    rulesCount: 0,
    workflowCount: 205,
    policies: fillSnapshotPolicies([
      snapshotPolicy("agent-instructions", "LOCAL", "AGENTS.md", null),
      snapshotPolicy("codeowners", "LOCAL", ".github/CODEOWNERS", "7b316c63d4e12f5c1abb13e5c57c45c8ad224399"),
      snapshotPolicy("security", "LOCAL", "SECURITY.md", null),
      snapshotPolicy("contributing", "LOCAL", "CONTRIBUTING.md", null),
      snapshotPolicy("code-of-conduct", "LOCAL", "CODE_OF_CONDUCT.md", "77998183229f90ffca47714c08c77a300dcee686"),
      snapshotPolicy("support", "LOCAL", "SUPPORT.md", null),
      snapshotPolicy("governance", "LOCAL", "GOVERNANCE.md", null),
      snapshotPolicy("license", "LOCAL", "LICENSE", "d645695673349e3947e8e5ae42332d0ac3164cd7"),
      snapshotPolicy("workflows", "LOCAL", ".github/workflows/*", null, null, 205),
    ]),
    consistency: null,
    evidenceCoverage: 0,
    agentSignals: [
      {
        classification: "AGENT_ASSISTANCE_DECLARED",
        repository: "szl-holdings/a11oy",
        path: "AGENTS.md",
        commitSha: "213898846413cc7b068198e945d58fcc6cb1629c",
        message: "Update AGENTS.md",
        actor: "Cursor Agent (declared co-author)",
        verified: true,
        url: "https://github.com/szl-holdings/a11oy/commit/213898846413cc7b068198e945d58fcc6cb1629c",
        evidence: "Commit message contains explicit Cursor Agent sign-off and co-author metadata.",
      },
    ],
  },
  {
    name: "killinchu",
    fullName: "szl-holdings/killinchu",
    description: null,
    defaultBranch: "main",
    headSha: "c26ccab84557",
    treeSha: null,
    treeComplete: false,
    protected: true,
    archived: false,
    language: "Python",
    updatedAt: SNAPSHOT_AT,
    communityHealth: 87,
    rulesCount: 0,
    workflowCount: 62,
    policies: fillSnapshotPolicies([
      snapshotPolicy("agent-instructions", "ABSENT", null, null),
      snapshotPolicy("codeowners", "LOCAL", ".github/CODEOWNERS", "7b316c63d4e12f5c1abb13e5c57c45c8ad224399"),
      snapshotPolicy("security", "LOCAL", "SECURITY.md", null),
      snapshotPolicy("contributing", "LOCAL", "CONTRIBUTING.md", null),
      snapshotPolicy("code-of-conduct", "LOCAL", "CODE_OF_CONDUCT.md", "77998183229f90ffca47714c08c77a300dcee686"),
      snapshotPolicy("support", "LOCAL", "SUPPORT.md", null),
      snapshotPolicy("license", "LOCAL", "LICENSE", "d645695673349e3947e8e5ae42332d0ac3164cd7"),
      snapshotPolicy("workflows", "LOCAL", ".github/workflows/*", null, null, 62),
    ]),
    consistency: null,
    evidenceCoverage: 0,
    agentSignals: [],
  },
  {
    name: "platform",
    fullName: "szl-holdings/platform",
    description: "Canonical platform spine",
    defaultBranch: "main",
    headSha: "ff8e29514a65",
    treeSha: null,
    treeComplete: false,
    protected: true,
    archived: false,
    language: "Python",
    updatedAt: SNAPSHOT_AT,
    communityHealth: 87,
    rulesCount: 5,
    workflowCount: 46,
    policies: fillSnapshotPolicies([
      snapshotPolicy("agent-instructions", "LOCAL", "AGENTS.md", null),
      snapshotPolicy("codeowners", "LOCAL", ".github/CODEOWNERS", "7b316c63d4e12f5c1abb13e5c57c45c8ad224399"),
      snapshotPolicy("security", "LOCAL", "SECURITY.md", null),
      snapshotPolicy("contributing", "LOCAL", "CONTRIBUTING.md", null),
      snapshotPolicy("code-of-conduct", "LOCAL", "CODE_OF_CONDUCT.md", "1fed02419b079b864abfef438ece078d64b7062e"),
      snapshotPolicy("support", "LOCAL", "SUPPORT.md", null),
      snapshotPolicy("license", "LOCAL", "LICENSE", null),
      snapshotPolicy("workflows", "LOCAL", ".github/workflows/*", null, null, 46),
    ]),
    consistency: null,
    evidenceCoverage: 0,
    agentSignals: [],
  },
  {
    name: "szl-router",
    fullName: "szl-holdings/szl-router",
    description: null,
    defaultBranch: "main",
    headSha: "ba225b2f2e57",
    treeSha: null,
    treeComplete: false,
    protected: true,
    archived: false,
    language: "Python",
    updatedAt: SNAPSHOT_AT,
    communityHealth: 87,
    rulesCount: 0,
    workflowCount: 10,
    policies: fillSnapshotPolicies([
      snapshotPolicy("agent-instructions", "ABSENT", null, null),
      snapshotPolicy("codeowners", "LOCAL", ".github/CODEOWNERS", "7b316c63d4e12f5c1abb13e5c57c45c8ad224399"),
      snapshotPolicy("security", "LOCAL", "SECURITY.md", null),
      snapshotPolicy("contributing", "LOCAL", "CONTRIBUTING.md", null),
      snapshotPolicy("code-of-conduct", "INHERITED", ".github/CODE_OF_CONDUCT.md", "415a0a14aebe0102d5db82dcc51dde5db16619f0", "szl-holdings/.github"),
      snapshotPolicy("support", "INHERITED", "SUPPORT.md", null, "szl-holdings/.github"),
      snapshotPolicy("license", "LOCAL", "LICENSE", null),
      snapshotPolicy("workflows", "LOCAL", ".github/workflows/*", null, null, 10),
    ]),
    consistency: null,
    evidenceCoverage: 0,
    agentSignals: [],
  },
  {
    name: "szl-frontier",
    fullName: "szl-holdings/szl-frontier",
    description: null,
    defaultBranch: "main",
    headSha: "10d88c01f174",
    treeSha: null,
    treeComplete: false,
    protected: true,
    archived: false,
    language: "Python",
    updatedAt: SNAPSHOT_AT,
    communityHealth: 100,
    rulesCount: 0,
    workflowCount: 7,
    policies: fillSnapshotPolicies([
      snapshotPolicy("agent-instructions", "ABSENT", null, null),
      snapshotPolicy("codeowners", "ABSENT", null, null),
      snapshotPolicy("security", "LOCAL", "SECURITY.md", null),
      snapshotPolicy("contributing", "INHERITED", "CONTRIBUTING.md", null, "szl-holdings/.github"),
      snapshotPolicy("code-of-conduct", "INHERITED", ".github/CODE_OF_CONDUCT.md", "415a0a14aebe0102d5db82dcc51dde5db16619f0", "szl-holdings/.github"),
      snapshotPolicy("support", "INHERITED", "SUPPORT.md", null, "szl-holdings/.github"),
      snapshotPolicy("license", "LOCAL", "LICENSE", "d645695673349e3947e8e5ae42332d0ac3164cd7"),
      snapshotPolicy("workflows", "LOCAL", ".github/workflows/*", null, null, 7),
    ]),
    consistency: null,
    evidenceCoverage: 0,
    agentSignals: [],
  },
];

function fingerprint(observation: PolicyObservation): string | null {
  if (observation.state === "ABSENT") return "MISSING";
  if (observation.state === "UNKNOWN") return null;
  return observation.blobSha;
}

export function scoreRepositories(repositories: RepoAudit[]) {
  for (const repository of repositories) {
    let observedWeight = 0;
    let comparableWeight = 0;
    let agreementWeight = 0;
    let applicableWeight = 0;
    for (const observation of repository.policies) {
      applicableWeight += observation.weight;
      const value = fingerprint(observation);
      if (!value) continue;
      observedWeight += observation.weight;
      const peers = repositories
        .filter((candidate) => candidate !== repository)
        .map((candidate) => fingerprint(candidate.policies.find((item) => item.key === observation.key)!))
        .filter((candidate): candidate is string => Boolean(candidate));
      if (!peers.length) continue;
      comparableWeight += observation.weight;
      const matches = peers.filter((candidate) => candidate === value).length;
      agreementWeight += (matches / peers.length) * observation.weight;
    }
    repository.evidenceCoverage = applicableWeight ? Math.round((observedWeight / applicableWeight) * 100) : 0;
    repository.consistency = comparableWeight ? Math.round((agreementWeight / comparableWeight) * 100) : null;
  }

  let agreementNumerator = 0;
  let agreementDenominator = 0;
  for (const definition of POLICY_DEFINITIONS) {
    const counts = new Map<string, number>();
    for (const repository of repositories) {
      const value = fingerprint(repository.policies.find((item) => item.key === definition.key)!);
      if (value) counts.set(value, (counts.get(value) ?? 0) + 1);
    }
    const n = [...counts.values()].reduce((sum, count) => sum + count, 0);
    if (n < 2) continue;
    const agreePairs = [...counts.values()].reduce((sum, count) => sum + count * (count - 1), 0);
    const agreement = agreePairs / (n * (n - 1));
    agreementNumerator += agreement * definition.weight;
    agreementDenominator += definition.weight;
  }

  const totalWeight = repositories.length * POLICY_DEFINITIONS.reduce((sum, definition) => sum + definition.weight, 0);
  const observedWeight = repositories.reduce(
    (sum, repository) => sum + repository.policies.reduce((subtotal, observation) => subtotal + (fingerprint(observation) ? observation.weight : 0), 0),
    0,
  );

  return {
    alignment: null as null,
    consistency: agreementDenominator ? Math.round((agreementNumerator / agreementDenominator) * 100) : null,
    evidenceCoverage: totalWeight ? Math.round((observedWeight / totalWeight) * 100) : 0,
  };
}

export function modeForDeepFailures(failedCount: number): EvidenceMode {
  return failedCount > 0 ? "BLOCKED" : "MEASURED";
}

export function deepInspectionBlocked(repository: RepoAudit): boolean {
  return Boolean(repository.error) || !repository.treeComplete || repository.policyHistory?.status === "BLOCKED";
}

export const SNAPSHOT_RESULT: AuditResult = {
  schemaVersion: 1,
  mode: "SAMPLE",
  publicOnly: true,
  org: {
    login: "szl-holdings",
    name: "SZL Holdings",
    description: "Governed AI infrastructure for inspectable decisions: source, runtime state, receipts, and proof boundaries.",
    htmlUrl: "https://github.com/szl-holdings",
    publicRepos: 117,
  },
  observedAt: SNAPSHOT_AT,
  startedAt: SNAPSHOT_AT,
  completedAt: SNAPSHOT_AT,
  inventory: { publicRepos: 117, active: 89, archived: 28, forks: 0 },
  sampleSize: snapshotRepos.length,
  repositories: snapshotRepos,
  scores: scoreRepositories(snapshotRepos),
  rate: UNKNOWN_RATE,
  sourceUrls: [
    "https://api.github.com/orgs/szl-holdings",
    "https://api.github.com/orgs/szl-holdings/repos?type=public&sort=updated&direction=desc&per_page=100&page=1",
    "https://api.github.com/orgs/szl-holdings/repos?type=public&sort=updated&direction=desc&per_page=100&page=2",
  ],
  limitations: [
    "Public repositories only; private and internal repositories are not visible.",
    "Deep policy evidence is a representative six-repository snapshot, not an estate-wide certification.",
    "The bundled SAMPLE preserves recorded abbreviated head prefixes, not exact full commit or tree bindings; incomplete fields remain UNKNOWN and synthetic fingerprints are not used.",
    "No declared, pinned curation manifest was found; consistency is descriptive and policy alignment is intentionally suppressed.",
    "Agent-change evidence is a bounded sample and does not establish exhaustive policy authorship or history.",
  ],
};

export class GitHubAuditError extends Error {
  public readonly status?: number;

  constructor(message: string, status?: number) {
    super(message);
    this.name = "GitHubAuditError";
    this.status = status;
  }
}

function updateRate(response: Response, onRate: (rate: RateState) => void) {
  const limit = response.headers.get("x-ratelimit-limit");
  const remaining = response.headers.get("x-ratelimit-remaining");
  const reset = response.headers.get("x-ratelimit-reset");
  onRate({
    limit: limit ? Number(limit) : null,
    remaining: remaining ? Number(remaining) : null,
    resetAt: reset ? new Date(Number(reset) * 1000).toISOString() : null,
  });
}

async function githubFetch<T>(url: string, onRate: (rate: RateState) => void): Promise<T> {
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), 15_000);
  try {
    const response = await fetch(url, {
      headers: {
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
      },
      signal: controller.signal,
    });
    updateRate(response, onRate);
    if (!response.ok) {
      let detail = response.statusText;
      try {
        const body = (await response.json()) as { message?: string };
        if (body.message) detail = body.message;
      } catch {
        // Keep the HTTP status text when an error body is not JSON.
      }
      throw new GitHubAuditError(`${response.status}: ${detail}`, response.status);
    }
    return (await response.json()) as T;
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") {
      throw new GitHubAuditError("GitHub did not respond within 15 seconds.");
    }
    throw error;
  } finally {
    window.clearTimeout(timeout);
  }
}

async function githubMaybe<T>(url: string, onRate: (rate: RateState) => void): Promise<T | null> {
  try {
    return await githubFetch<T>(url, onRate);
  } catch (error) {
    if (error instanceof GitHubAuditError && [404, 422].includes(error.status ?? 0)) return null;
    throw error;
  }
}

function resolvePolicies(
  entries: TreeEntry[],
  treeComplete: boolean,
  defaultEntries: TreeEntry[] | null,
  defaultTreeComplete: boolean,
  defaultRepo: string,
): PolicyObservation[] {
  return POLICY_DEFINITIONS.map((definition) => {
    if (definition.setPrefix) {
      const members = entries
        .filter((entry) => entry.type === "blob" && entry.path.startsWith(definition.setPrefix!) && /\.ya?ml$/i.test(entry.path))
        .sort((a, b) => a.path.localeCompare(b.path));
      if (members.length) {
        return {
          key: definition.key,
          label: definition.label,
          weight: definition.weight,
          state: "LOCAL" as const,
          path: `${definition.setPrefix}*`,
          blobSha: `set:${members.map((entry) => `${entry.path}:${entry.sha}`).join("|")}`,
          sourceRepo: null,
          memberCount: members.length,
        };
      }
      return {
        key: definition.key,
        label: definition.label,
        weight: definition.weight,
        state: treeComplete ? ("ABSENT" as const) : ("UNKNOWN" as const),
        path: null,
        blobSha: null,
        sourceRepo: null,
        memberCount: 0,
      };
    }

    const local = definition.candidates
      .map((path) => entries.find((entry) => entry.type === "blob" && entry.path === path))
      .find(Boolean);
    if (local) {
      return {
        key: definition.key,
        label: definition.label,
        weight: definition.weight,
        state: "LOCAL" as const,
        path: local.path,
        blobSha: local.sha,
        sourceRepo: null,
      };
    }

    if (!treeComplete) {
      return {
        key: definition.key,
        label: definition.label,
        weight: definition.weight,
        state: "UNKNOWN" as const,
        path: null,
        blobSha: null,
        sourceRepo: null,
      };
    }

    if (definition.inheritable && defaultEntries) {
      const inherited = definition.candidates
        .map((path) => defaultEntries.find((entry) => entry.type === "blob" && entry.path === path))
        .find(Boolean);
      if (inherited) {
        return {
          key: definition.key,
          label: definition.label,
          weight: definition.weight,
          state: "INHERITED" as const,
          path: inherited.path,
          blobSha: inherited.sha,
          sourceRepo: defaultRepo,
        };
      }
      if (!defaultTreeComplete) {
        return {
          key: definition.key,
          label: definition.label,
          weight: definition.weight,
          state: "UNKNOWN" as const,
          path: null,
          blobSha: null,
          sourceRepo: defaultRepo,
        };
      }
    }

    return {
      key: definition.key,
      label: definition.label,
      weight: definition.weight,
      state: "ABSENT" as const,
      path: null,
      blobSha: null,
      sourceRepo: null,
    };
  });
}

export function classifyAgentSignal(
  repository: string,
  path: string,
  item: {
    sha: string;
    html_url: string;
    author: { login?: string; type?: string } | null;
    committer: { login?: string; type?: string } | null;
    commit: { message: string; verification?: { verified?: boolean } };
  },
): AgentSignal | null {
  const message = item.commit.message ?? "";
  const declared = /CURSOR_AGENT_PR_BODY|co-authored-by:\s*[^\n]*(?:cursor|claude|copilot|agent|\bai\b)/i.test(message);
  const automation = item.author?.type === "Bot" || item.committer?.type === "Bot";
  if (!declared && !automation) return null;
  const actor = item.author?.login ?? item.committer?.login ?? "unidentified actor";
  return {
    classification: declared ? "AGENT_ASSISTANCE_DECLARED" : "AUTOMATION_ACTOR_OBSERVED",
    repository,
    path,
    commitSha: item.sha,
    message: message.split("\n")[0] || "Policy change",
    actor,
    verified: item.commit.verification?.verified ?? null,
    url: item.html_url,
    evidence: declared
      ? "The commit message declares agent assistance. This declaration is not independent verification."
      : "GitHub attributes the action to a Bot/App identity. That does not prove an AI system wrote every changed byte.",
  };
}

export function matchPolicyChanges(files: Array<{ filename: string; previous_filename?: string }>) {
  const paths = new Set<string>();
  const keys = new Set<string>();
  for (const file of files) {
    for (const path of [file.filename, file.previous_filename].filter((value): value is string => Boolean(value))) {
      for (const definition of POLICY_DEFINITIONS) {
        if (definition.candidates.includes(path) ||
          (definition.setPrefix && path.startsWith(definition.setPrefix) && /\.ya?ml$/i.test(path))) {
          paths.add(path);
          keys.add(definition.key);
        }
      }
    }
  }
  return { changedPaths: [...paths].sort(), policyKeys: [...keys].sort() };
}

export function normalizeOrganizationHandle(rawOrg: string): string {
  const org = rawOrg.trim().replace(/^https?:\/\/github\.com\//i, "").replace(/^@/, "").replace(/\/$/, "");
  if (!/^[a-z\d](?:[a-z\d-]{0,37}[a-z\d])?$/i.test(org)) throw new GitHubAuditError("Enter a valid GitHub organization handle.");
  return org;
}

export async function scanOrganization(
  rawOrg: string,
  sampleSize: number,
  onProgress: (message: string, completed: number, total: number) => void,
  onRate: (rate: RateState) => void,
): Promise<AuditResult> {
  const org = normalizeOrganizationHandle(rawOrg);

  const startedAt = new Date().toISOString();
  if (![4, 6, 8].includes(sampleSize)) throw new GitHubAuditError("Choose a deep sample of 4, 6, or 8 repositories.");
  let currentRate = UNKNOWN_RATE;
  const captureRate = (rate: RateState) => {
    const sameWindow = !currentRate.resetAt || !rate.resetAt || currentRate.resetAt === rate.resetAt;
    if (sameWindow) {
      const remaining = currentRate.remaining === null
        ? rate.remaining
        : rate.remaining === null
          ? currentRate.remaining
          : Math.min(currentRate.remaining, rate.remaining);
      currentRate = {
        limit: rate.limit ?? currentRate.limit,
        remaining,
        resetAt: rate.resetAt ?? currentRate.resetAt,
      };
    } else {
      currentRate = rate;
    }
    onRate(currentRate);
  };

  onProgress("Verifying the public organization", 0, 1);
  const orgData = await githubFetch<{
    login: string;
    name: string | null;
    description: string | null;
    html_url: string;
    public_repos: number;
  }>(`https://api.github.com/orgs/${encodeURIComponent(org)}`, captureRate);

  const repositories: RepoApi[] = [];
  let page = 1;
  while (true) {
    onProgress(`Loading public repository inventory · page ${page}`, page - 1, Math.max(2, Math.ceil(orgData.public_repos / 100)));
    const batch = await githubFetch<RepoApi[]>(
      `https://api.github.com/orgs/${encodeURIComponent(orgData.login)}/repos?type=public&sort=updated&direction=desc&per_page=100&page=${page}`,
      captureRate,
    );
    for (const repository of batch) {
      if (!repositories.some((existing) => existing.full_name.toLowerCase() === repository.full_name.toLowerCase())) repositories.push(repository);
    }
    if (batch.length < 100) break;
    page += 1;
    if (page > 10) throw new GitHubAuditError("Repository inventory exceeded the browser audit safety limit.");
  }

  const eligible = repositories.filter((repository) => !repository.archived && !repository.disabled && !repository.fork);
  const defaultRepo = eligible.find((repository) => repository.name === ".github") ?? null;
  const selectedMap = new Map<string, RepoApi>();
  if (defaultRepo) selectedMap.set(defaultRepo.full_name, defaultRepo);
  for (const repository of eligible) {
    if (selectedMap.size >= sampleSize) break;
    selectedMap.set(repository.full_name, repository);
  }
  const selected = [...selectedMap.values()];

  let completed = 0;
  const builds: RepoBuild[] = [];
  const auditOne = async (repository: RepoApi): Promise<RepoBuild> => {
    onProgress(`Resolving ${repository.name} to an immutable head`, completed, selected.length);
    try {
      const branch = await githubFetch<{
        name: string;
        protected: boolean;
        commit: { sha: string; commit: { tree: { sha: string } } };
      }>(
        `https://api.github.com/repos/${repository.full_name}/branches/${encodeURIComponent(repository.default_branch)}`,
        captureRate,
      );
      const headSha = branch.commit.sha;
      const treeSha = branch.commit.commit.tree.sha;
      const [treeResult, communityResult, rulesResult] = await Promise.all([
        githubFetch<{ sha: string; truncated: boolean; tree: TreeEntry[] }>(
          `https://api.github.com/repos/${repository.full_name}/git/trees/${treeSha}?recursive=1`,
          captureRate,
        ),
        githubMaybe<{ health_percentage: number }>(
          `https://api.github.com/repos/${repository.full_name}/community/profile`,
          captureRate,
        ),
        githubMaybe<unknown[]>(
          `https://api.github.com/repos/${repository.full_name}/rules/branches/${encodeURIComponent(repository.default_branch)}?per_page=100`,
          captureRate,
        ),
      ]);

      const treeComplete = !treeResult.truncated;
      const preliminary = resolvePolicies(treeResult.tree, treeComplete, null, false, `${orgData.login}/.github`);
      const agentSignals: AgentSignal[] = [];
      const policyHistory: PolicyHistory = {
        sourceHeadSha: headSha,
        status: "MEASURED",
        commitsExamined: 0,
        attributedCandidates: 0,
        detailsExamined: 0,
        unexaminedCandidates: 0,
        fileListsTruncated: false,
      };
      try {
        const reserveForSource = () => 4 * Math.max(0, selected.length - completed - 1);
        if (currentRate.remaining !== null && currentRate.remaining < reserveForSource() + 3) {
          throw new GitHubAuditError("The remaining GitHub request budget is reserved for source inspections; recent policy history was not completed.");
        }
        const history = await githubMaybe<Array<{
          sha: string;
          html_url: string;
          author: { login?: string; type?: string } | null;
          committer: { login?: string; type?: string } | null;
          commit: { message: string; verification?: { verified?: boolean } };
        }>>(
          `https://api.github.com/repos/${repository.full_name}/commits?sha=${encodeURIComponent(headSha)}&per_page=20`,
          captureRate,
        );
        if (!history) throw new GitHubAuditError("Recent commit history is unavailable.");
        policyHistory.commitsExamined = history.length;
        const candidates = [...new Map(history.map((item) => classifyAgentSignal(repository.full_name, "", item))
          .filter((item): item is AgentSignal => Boolean(item))
          .map((item) => [item.commitSha, item])).values()];
        policyHistory.attributedCandidates = candidates.length;
        for (const candidate of candidates.slice(0, 2)) {
          if (currentRate.remaining !== null && currentRate.remaining < reserveForSource() + 1) {
            throw new GitHubAuditError("The remaining GitHub request budget is reserved for source inspections; further commit details were withheld.");
          }
          const detail = await githubFetch<{ sha: string; files?: Array<{ filename: string; previous_filename?: string }> }>(
            `https://api.github.com/repos/${repository.full_name}/commits/${candidate.commitSha}?per_page=100`,
            captureRate,
          );
          if (detail.sha !== candidate.commitSha || !detail.files) throw new GitHubAuditError("Commit detail is missing its immutable file binding.");
          policyHistory.detailsExamined += 1;
          // A full first page may have additional files. Conservatively withhold completeness.
          if (detail.files.length >= 100) policyHistory.fileListsTruncated = true;
          const matches = matchPolicyChanges(detail.files);
          if (matches.changedPaths.length) agentSignals.push({
            ...candidate,
            path: matches.changedPaths.join(", "),
            ...matches,
            sourceHeadSha: headSha,
          });
        }
        if (policyHistory.fileListsTruncated) policyHistory.status = "BLOCKED";
      } catch (error) {
        policyHistory.status = "BLOCKED";
        policyHistory.error = error instanceof Error ? error.message : "Policy history is unavailable.";
      }
      policyHistory.unexaminedCandidates = Math.max(0, policyHistory.attributedCandidates - policyHistory.detailsExamined);

      return {
        name: repository.name,
        fullName: repository.full_name,
        description: repository.description,
        defaultBranch: repository.default_branch,
        headSha,
        treeSha,
        treeComplete,
        protected: branch.protected,
        archived: repository.archived,
        language: repository.language,
        updatedAt: repository.updated_at,
        communityHealth: communityResult?.health_percentage ?? null,
        rulesCount: rulesResult?.length ?? null,
        workflowCount: preliminary.find((item) => item.key === "workflows")?.memberCount ?? 0,
        policies: preliminary,
        consistency: null,
        evidenceCoverage: 0,
        agentSignals,
        policyHistory,
        entries: treeResult.tree,
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : "Repository audit failed.";
      return {
        name: repository.name,
        fullName: repository.full_name,
        description: repository.description,
        defaultBranch: repository.default_branch,
        headSha: null,
        treeSha: null,
        treeComplete: false,
        protected: null,
        archived: repository.archived,
        language: repository.language,
        updatedAt: repository.updated_at,
        communityHealth: null,
        rulesCount: null,
        workflowCount: 0,
        policies: POLICY_DEFINITIONS.map((definition) => ({
          key: definition.key,
          label: definition.label,
          weight: definition.weight,
          state: "UNKNOWN" as const,
          path: null,
          blobSha: null,
          sourceRepo: null,
        })),
        consistency: null,
        evidenceCoverage: 0,
        agentSignals: [],
        entries: [],
        error: message,
      };
    } finally {
      completed += 1;
      onProgress(`Audited ${completed} of ${selected.length} repositories`, completed, selected.length);
    }
  };

  for (let index = 0; index < selected.length; index += 2) {
    const batch = await Promise.all(selected.slice(index, index + 2).map(auditOne));
    builds.push(...batch);
  }

  const defaultBuild = builds.find((repository) => repository.name === ".github");
  for (const repository of builds) {
    repository.policies = resolvePolicies(
      repository.entries,
      repository.treeComplete,
      defaultBuild && defaultBuild !== repository ? defaultBuild.entries : null,
      defaultBuild?.treeComplete ?? !defaultRepo,
      `${orgData.login}/.github`,
    );
    repository.workflowCount = repository.policies.find((item) => item.key === "workflows")?.memberCount ?? 0;
  }

  const publicRepositories = repositories.length;
  const scores = scoreRepositories(builds);
  const completedAt = new Date().toISOString();
  const failedCount = builds.filter((repository) => Boolean(repository.error)).length;
  const truncatedCount = builds.filter((repository) => !repository.error && !repository.treeComplete).length;
  const blockedCount = builds.filter(deepInspectionBlocked).length;
  const historyBlockedCount = builds.filter((repository) => repository.policyHistory?.status === "BLOCKED").length;
  const sourceUrls = [
    `https://api.github.com/orgs/${orgData.login}`,
    ...Array.from({ length: page }, (_, index) => `https://api.github.com/orgs/${orgData.login}/repos?type=public&sort=updated&direction=desc&per_page=100&page=${index + 1}`),
  ];

  return {
    schemaVersion: 1,
    mode: modeForDeepFailures(blockedCount),
    publicOnly: true,
    org: {
      login: orgData.login,
      name: orgData.name ?? orgData.login,
      description: orgData.description,
      htmlUrl: orgData.html_url,
      publicRepos: orgData.public_repos,
    },
    observedAt: completedAt,
    startedAt,
    completedAt,
    inventory: {
      publicRepos: publicRepositories,
      active: repositories.filter((repository) => !repository.archived && !repository.disabled).length,
      archived: repositories.filter((repository) => repository.archived).length,
      forks: repositories.filter((repository) => repository.fork).length,
    },
    sampleSize: builds.length,
    publicInventory: repositories.map((repository) => ({ fullName: repository.full_name, archived: repository.archived, fork: repository.fork, disabled: repository.disabled })),
    repositories: builds.map(({ entries, ...repository }) => {
      void entries;
      return repository;
    }),
    scores,
    rate: currentRate,
    sourceUrls,
    limitations: [
      "Public repositories only; private and internal repositories are not visible.",
      "The paginated inventory is collected across the scan window rather than as one atomic snapshot; duplicate repository identities are removed.",
      `Deep policy inspection is limited to ${builds.length} active repositories to preserve the unauthenticated GitHub request budget.`,
      "No declared, pinned curation manifest was supplied; consistency is descriptive and policy alignment is intentionally suppressed.",
      "A protected branch signal and a public ruleset response are separate evidence surfaces; an empty ruleset list does not mean unprotected.",
      "Policy-change signals inspect the latest 20 commits from each captured head and the file lists of at most two explicitly agent-declared or Bot/App commits. All supported policy paths are matched, including deleted and renamed paths. Older commits and uninspected candidates remain unclassified; inherited changes are counted once at their source repository.",
      ...(historyBlockedCount ? [`${historyBlockedCount} policy-history inspections were incomplete or unavailable. Captured head and policy evidence is retained, while overall audit status remains BLOCKED.`] : []),
      ...(failedCount
        ? [`${failedCount} of ${builds.length} deep repository inspections were unavailable; the result is BLOCKED rather than a complete measured audit.`]
        : []),
      ...(truncatedCount
        ? [`${truncatedCount} of ${builds.length} recursive Git trees were truncated by GitHub; their unresolved policy inputs remain UNKNOWN and the result is BLOCKED.`]
        : []),
    ],
  };
}

export function agentSignalCount(result: AuditResult) {
  return result.repositories.reduce((sum, repository) => sum + repository.agentSignals.length, 0);
}

export function policyPresence(repository: RepoAudit) {
  return repository.policies.filter((policy) => policy.state === "LOCAL" || policy.state === "INHERITED").length;
}

export function canonicalize(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value) ?? "null";
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  const object = value as Record<string, unknown>;
  return `{${Object.keys(object)
    .filter((key) => object[key] !== undefined)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalize(object[key])}`)
    .join(",")}}`;
}

export async function createReceipt(result: AuditResult) {
  const payload = {
    receiptSchema: "curation-atlas/1",
    generatedAt: new Date().toISOString(),
    claim: "Local public GitHub observation and deterministic derivation; not a GitHub attestation or third-party signature.",
    audit: result,
  };
  const canonical = canonicalize(payload);
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical));
  const sha256 = [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
  return { ...payload, receiptSha256: sha256 };
}
