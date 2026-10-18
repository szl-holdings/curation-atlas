import { POLICY_DEFINITIONS, type AuditResult } from "./audit.ts";

const SHA = /^[0-9a-f]{40}$/i;
const MODES = new Set(["MEASURED", "BLOCKED"]);
const POLICY_STATES = new Set(["LOCAL", "INHERITED", "ABSENT", "UNKNOWN"]);

export class BackendAuditError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "BackendAuditError";
  }
}

export function configuredAtlasApiBase(raw = process.env.NEXT_PUBLIC_ATLAS_API_BASE): string | null {
  if (!raw?.trim()) return null;
  let url: URL;
  try {
    url = new URL(raw.trim());
  } catch {
    throw new BackendAuditError("The configured Atlas API URL is invalid.");
  }
  const local = url.protocol === "http:" && ["localhost", "127.0.0.1"].includes(url.hostname);
  if ((!local && url.protocol !== "https:") || url.username || url.password ||
      url.pathname !== "/" || url.search || url.hash) {
    throw new BackendAuditError("The Atlas API must use an exact HTTPS origin (or loopback for development).");
  }
  return url.origin;
}

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function percentage(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= 100;
}

export function parseBackendAudit(value: unknown, requestedSample: number): AuditResult {
  if (!record(value) || value.schemaVersion !== 1 || value.publicOnly !== true ||
      !MODES.has(String(value.mode)) || !record(value.org) || value.org.login !== "szl-holdings" ||
      !record(value.inventory) || !record(value.scores) || value.scores.alignment !== null ||
      !record(value.rate) || !Array.isArray(value.repositories) ||
      !Array.isArray(value.publicInventory) || !Array.isArray(value.sourceUrls) ||
      !Array.isArray(value.limitations) || value.sampleSize !== requestedSample ||
      value.repositories.length !== requestedSample ||
      !percentage(value.scores.evidenceCoverage) ||
      (value.scores.consistency !== null && !percentage(value.scores.consistency)) ||
      !value.sourceUrls.every((url) => typeof url === "string" && url.startsWith("https://api.github.com/")) ||
      !value.limitations.every((item) => typeof item === "string") ||
      typeof value.observedAt !== "string" || !Number.isFinite(Date.parse(value.observedAt))) {
    throw new BackendAuditError("The Python API did not return a compatible public AuditResult v1.");
  }
  for (const repo of value.repositories) {
    if (!record(repo) || typeof repo.fullName !== "string" ||
        !repo.fullName.toLowerCase().startsWith("szl-holdings/") ||
        !Array.isArray(repo.policies) || repo.policies.length !== POLICY_DEFINITIONS.length ||
        !Array.isArray(repo.agentSignals) ||
        (repo.headSha !== null && (typeof repo.headSha !== "string" || !SHA.test(repo.headSha))) ||
        (repo.treeSha !== null && (typeof repo.treeSha !== "string" || !SHA.test(repo.treeSha))) ||
        (repo.treeComplete === true && (!repo.headSha || !repo.treeSha))) {
      throw new BackendAuditError("The Python API returned an incomplete repository source binding.");
    }
    const canonical = new Map(POLICY_DEFINITIONS.map((definition) => [definition.key, definition]));
    const seen = new Set<string>();
    for (const policy of repo.policies) {
      const definition = record(policy) && typeof policy.key === "string"
        ? canonical.get(policy.key) : undefined;
      if (!record(policy) || !definition || seen.has(definition.key) ||
          policy.label !== definition.label || policy.weight !== definition.weight ||
          !POLICY_STATES.has(String(policy.state)) ||
          (policy.blobSha !== null && typeof policy.blobSha !== "string") ||
          (["LOCAL", "INHERITED"].includes(String(policy.state)) &&
            (typeof policy.path !== "string" || !policy.path ||
              typeof policy.blobSha !== "string" || !policy.blobSha)) ||
          (["ABSENT", "UNKNOWN"].includes(String(policy.state)) &&
            (policy.path !== null || policy.blobSha !== null)) ||
          (policy.state === "INHERITED" && policy.sourceRepo !== "szl-holdings/.github") ||
          (policy.state === "UNKNOWN" && policy.sourceRepo !== null &&
            policy.sourceRepo !== "szl-holdings/.github") ||
          (["LOCAL", "ABSENT"].includes(String(policy.state)) && policy.sourceRepo !== null) ||
          (value.mode === "MEASURED" && ["LOCAL", "INHERITED"].includes(String(policy.state)) &&
            (typeof policy.blobSha !== "string" ||
              !(SHA.test(policy.blobSha) || policy.blobSha.startsWith("set:"))))) {
        throw new BackendAuditError("The Python API returned an invalid policy observation.");
      }
      seen.add(definition.key);
    }
    for (const signal of repo.agentSignals) {
      if (!record(signal) || typeof signal.url !== "string" ||
          !/^https:\/\/github\.com\/szl-holdings\/[^/]+\/commit\/[0-9a-f]{40}$/i.test(signal.url)) {
        throw new BackendAuditError("The Python API returned an unsafe policy-history URL.");
      }
    }
  }
  if (value.mode === "MEASURED" && value.repositories.some((repo) =>
    record(repo) && (repo.error || repo.treeComplete !== true ||
      !record(repo.policyHistory) || repo.policyHistory.status !== "MEASURED"))) {
    throw new BackendAuditError("The Python API labeled incomplete source evidence MEASURED.");
  }
  return value as AuditResult;
}

export async function scanBackendOrganization(
  origin: string,
  sampleSize: number,
  fetcher: typeof fetch = fetch,
): Promise<AuditResult> {
  if (![4, 6, 8].includes(sampleSize)) throw new BackendAuditError("Choose 4, 6, or 8 deep repositories.");
  const base = configuredAtlasApiBase(origin);
  if (!base) throw new BackendAuditError("The Python API origin is not configured.");
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 125_000);
  try {
    const url = new URL("/v1/orgs/szl-holdings/audit?sample_size=" + sampleSize, base);
    const response = await fetcher(url.toString(), {
      method: "GET",
      headers: { Accept: "application/json" },
      credentials: "omit",
      redirect: "error",
      cache: "no-store",
      signal: controller.signal,
    });
    if (!response.ok) {
      throw new BackendAuditError("Python API unavailable (HTTP " + response.status + "); existing evidence was not replaced.");
    }
    return parseBackendAudit(await response.json(), sampleSize);
  } catch (error) {
    if (error instanceof BackendAuditError) throw error;
    if (error instanceof DOMException && error.name === "AbortError") {
      throw new BackendAuditError("Python API timed out; existing evidence was not replaced.");
    }
    throw new BackendAuditError("Python API could not be reached; existing evidence was not replaced.");
  } finally {
    clearTimeout(timeout);
  }
}
