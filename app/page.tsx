"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Activity,
  AlertTriangle,
  Bot,
  Braces,
  Check,
  CircleDot,
  Clock3,
  Database,
  FileCheck2,
  Fingerprint,
  GitBranch,
  Info,
  Layers3,
  LockKeyhole,
  Network,
  Orbit,
  Radar,
  RefreshCw,
  Search,
  Sparkles,
  TriangleAlert,
} from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { NativeSelect, NativeSelectOption } from "@/components/ui/native-select";
import { Progress } from "@/components/ui/progress";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  type AuditResult,
  type PolicyObservation,
  type RepoAudit,
  SNAPSHOT_RESULT,
  agentSignalCount,
  createReceipt,
  deepInspectionBlocked,
  policyPresence,
  scanOrganization,
} from "@/lib/audit";
import { doctrineReadback } from "@/lib/doctrine";
import { comparisonRows, frontierHypothesis, methods, sources } from "@/lib/research";
import { compareAudits, verifyImportedReceipt, type VerifiedBaseline } from "@/lib/comparison";

type ScanProgress = { message: string; completed: number; total: number };

type WebMcpTool = {
  name: string;
  title?: string;
  description: string;
  inputSchema: Record<string, unknown>;
  annotations?: { readOnlyHint?: boolean; untrustedContentHint?: boolean };
  execute(input: unknown): unknown | Promise<unknown>;
};

declare global {
  interface Document {
    readonly modelContext?: {
      registerTool(tool: WebMcpTool, options?: { signal?: AbortSignal }): void | Promise<void>;
    };
  }
}

const STATE_STYLE: Record<PolicyObservation["state"], string> = {
  LOCAL: "border-emerald-300/20 bg-emerald-300/[0.07] text-emerald-200",
  INHERITED: "border-sky-300/20 bg-sky-300/[0.07] text-sky-200",
  ABSENT: "border-amber-300/20 bg-amber-300/[0.07] text-amber-200",
  UNKNOWN: "border-white/10 bg-white/[0.035] text-slate-400",
};

function formatObserved(iso: string) {
  return new Intl.DateTimeFormat("en", {
    dateStyle: "medium",
    timeStyle: "short",
    timeZone: "UTC",
  }).format(new Date(iso)) + " UTC";
}

function shortSha(sha: string | null) {
  return sha ? sha.slice(0, 12) : "unavailable";
}

function toneFor(score: number | null) {
  if (score === null) return "muted";
  if (score >= 80) return "good";
  if (score >= 55) return "warn";
  return "risk";
}

function signalLabel(classification: RepoAudit["agentSignals"][number]["classification"]) {
  if (classification === "AGENT_ASSISTANCE_DECLARED") return "DECLARED · agent assistance";
  if (classification === "AUTOMATION_ACTOR_OBSERVED") return "MEASURED · automation actor";
  return "UNKNOWN · drafting process";
}

function Metric({
  icon: Icon,
  label,
  value,
  detail,
  tone = "default",
}: {
  icon: typeof Activity;
  label: string;
  value: string;
  detail: string;
  tone?: "default" | "mint" | "amber";
}) {
  return (
    <article className={`metric-card metric-${tone}`}>
      <div className="flex items-start justify-between gap-3">
        <div>
          <p className="metric-label">{label}</p>
          <p className="mt-3 font-mono text-3xl font-semibold tracking-[-0.06em] text-white">{value}</p>
        </div>
        <Icon className="h-4 w-4 text-slate-400" aria-hidden="true" />
      </div>
      <p className="mt-3 text-sm leading-5 text-slate-400">{detail}</p>
    </article>
  );
}

function DriftMap({ repositories, onSelect }: { repositories: RepoAudit[]; onSelect: (repo: RepoAudit) => void }) {
  const points = useMemo(() => {
    const centerIndex = Math.max(0, repositories.findIndex((repo) => repo.name === ".github"));
    const center = repositories[centerIndex];
    const satellites = repositories.filter((_, index) => index !== centerIndex);
    const computed = satellites.map((repo, index) => {
      const angle = (Math.PI * 2 * index) / Math.max(satellites.length, 1) - Math.PI / 2;
      const radius = 23 + (100 - (repo.consistency ?? 50)) * 0.13;
      return {
        repo,
        x: 50 + Math.cos(angle) * radius,
        y: 50 + Math.sin(angle) * radius,
      };
    });
    return center ? [{ repo: center, x: 50, y: 50 }, ...computed] : computed;
  }, [repositories]);

  return (
    <div className="drift-map" role="group" aria-label="Repository policy consistency topology; activate a repository to inspect its evidence">
      <svg className="absolute inset-0 h-full w-full" viewBox="0 0 100 100" aria-hidden="true">
        <defs>
          <linearGradient id="edge" x1="0" x2="1">
            <stop offset="0" stopColor="#43f3c3" stopOpacity=".08" />
            <stop offset=".5" stopColor="#43f3c3" stopOpacity=".52" />
            <stop offset="1" stopColor="#43f3c3" stopOpacity=".08" />
          </linearGradient>
        </defs>
        {points.slice(1).map((point) => (
          <line key={point.repo.fullName} x1="50" y1="50" x2={point.x} y2={point.y} stroke="url(#edge)" strokeWidth=".42" />
        ))}
        <circle cx="50" cy="50" r="33" stroke="#26313b" strokeWidth=".25" fill="none" strokeDasharray="1.4 2" />
        <circle cx="50" cy="50" r="20" stroke="#26313b" strokeWidth=".25" fill="none" strokeDasharray="1.4 2" />
      </svg>
      <div className="map-axis map-axis-x" />
      <div className="map-axis map-axis-y" />
      {points.map((point, index) => (
        <button
          type="button"
          key={point.repo.fullName}
          className={`map-node map-node-${toneFor(point.repo.consistency)} ${index === 0 ? "map-node-anchor" : ""}`}
          style={{ left: `${point.x}%`, top: `${point.y}%` }}
          onClick={() => onSelect(point.repo)}
          aria-label={`${point.repo.name}, cohort consistency ${point.repo.consistency ?? "unknown"}`}
        >
          <span className="map-node-core">{point.repo.consistency ?? "?"}</span>
          <span className="map-node-name">{point.repo.name}</span>
        </button>
      ))}
      <div className="absolute bottom-4 left-4 right-4 flex flex-wrap items-center justify-between gap-2">
        <span className="rounded-full border border-white/10 bg-black/40 px-3 py-1 text-xs text-slate-400 backdrop-blur">
          radius = lower pairwise agreement
        </span>
        <span className="rounded-full border border-white/10 bg-black/40 px-3 py-1 font-mono text-xs text-slate-400 backdrop-blur">
          descriptive · not causal
        </span>
      </div>
    </div>
  );
}

function RepoInspector({ repository, open, onOpenChange }: { repository: RepoAudit | null; open: boolean; onOpenChange: (open: boolean) => void }) {
  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent className="w-[min(94vw,580px)] overflow-y-auto border-white/10 bg-[#090d12] p-0 sm:max-w-[580px]">
        {repository && (
          <>
            <SheetHeader className="border-b border-white/[0.08] p-6 pr-12">
              <div className="mb-2 flex items-center gap-2">
                <Badge variant="outline" className="border-white/10 bg-white/[0.03] font-mono text-[11px] text-slate-400">REPO EVIDENCE</Badge>
                {repository.protected === true && <Badge variant="outline" className="border-emerald-300/20 bg-emerald-300/[0.06] text-emerald-200"><LockKeyhole className="h-3 w-3" /> protected</Badge>}
              </div>
              <SheetTitle className="font-mono text-2xl tracking-[-0.04em] text-white">{repository.name}</SheetTitle>
              <SheetDescription className="leading-6 text-slate-400">
                {repository.description ?? "No public repository description."}
              </SheetDescription>
            </SheetHeader>
            <div className="space-y-7 p-6">
              {(repository.error || !repository.treeComplete) && (
                <Alert className="border-amber-300/20 bg-amber-300/[0.04] text-amber-100">
                  <AlertTriangle className="h-4 w-4" />
                  <AlertTitle>{repository.error ? "Deep inspection unavailable" : "Tree evidence incomplete"}</AlertTitle>
                  <AlertDescription className="text-amber-100/65">{repository.error ?? "The source record does not contain a complete recursive tree."} Unresolved policy inputs remain UNKNOWN and are excluded from scoring.</AlertDescription>
                </Alert>
              )}
              <section className="grid grid-cols-2 gap-3">
                <div className="rounded-xl border border-white/[0.08] bg-white/[0.025] p-4">
                  <p className="eyebrow">Captured head</p>
                  <p className="mt-2 font-mono text-sm text-slate-200">{shortSha(repository.headSha)}</p>
                </div>
                <div className="rounded-xl border border-white/[0.08] bg-white/[0.025] p-4">
                  <p className="eyebrow">Tree evidence</p>
                  <p className="mt-2 text-sm text-slate-200">{repository.treeComplete ? "Complete" : "Incomplete"}</p>
                </div>
                <div className="rounded-xl border border-white/[0.08] bg-white/[0.025] p-4">
                  <p className="eyebrow">Consistency</p>
                  <p className="mt-2 font-mono text-xl text-white">{repository.consistency ?? "—"}</p>
                </div>
                <div className="rounded-xl border border-white/[0.08] bg-white/[0.025] p-4">
                  <p className="eyebrow">Evidence coverage</p>
                  <p className="mt-2 font-mono text-xl text-white">{repository.evidenceCoverage}%</p>
                </div>
              </section>

              <section>
                <div className="mb-3 flex items-end justify-between gap-3">
                  <div>
                    <p className="eyebrow">What was observed</p>
                    <h3 className="mt-1 text-lg font-semibold text-white">Effective policy surface</h3>
                  </div>
                  <span className="font-mono text-xs text-slate-400">{policyPresence(repository)} / {repository.policies.length} present</span>
                </div>
                <div className="overflow-hidden rounded-xl border border-white/[0.08]">
                  {repository.policies.map((policy) => (
                    <div key={policy.key} className="grid grid-cols-[minmax(0,1fr)_auto] gap-4 border-b border-white/[0.07] p-4 last:border-b-0">
                      <div className="min-w-0">
                        <p className="text-sm font-medium text-slate-200">{policy.label}</p>
                        <p className="mt-1 truncate font-mono text-xs text-slate-400">
                          {policy.path ?? (policy.state === "ABSENT" ? "No effective file observed" : "Evidence unavailable")}
                        </p>
                        {policy.sourceRepo && <p className="mt-1 text-xs text-sky-300/70">via {policy.sourceRepo}</p>}
                      </div>
                      <div className="text-right">
                        <Badge variant="outline" className={`${STATE_STYLE[policy.state]} text-[10px]`}>{policy.state}</Badge>
                        {policy.blobSha && <p className="mt-2 font-mono text-[10px] text-slate-400">{policy.blobSha.slice(0, 9)}</p>}
                      </div>
                    </div>
                  ))}
                </div>
              </section>

              <section>
                <p className="eyebrow">Recent policy-change signals</p>
                <h3 className="mt-1 text-lg font-semibold text-white">Attribution without overclaiming</h3>
                <p className="mt-2 text-sm leading-6 text-slate-400">{repository.policyHistory ? `${repository.policyHistory.commitsExamined} recent commits examined · ${repository.policyHistory.detailsExamined} of ${repository.policyHistory.attributedCandidates} attributed commit details checked. ${repository.policyHistory.unexaminedCandidates} candidates remain unexamined.` : "Recorded sample history; comprehensive policy-change coverage is UNKNOWN."}</p>
                {repository.policyHistory?.status === "BLOCKED" && <p className="mt-2 text-sm leading-6 text-amber-200">BLOCKED · {repository.policyHistory.error ?? "A commit file list may continue beyond the inspected page."} Captured source and policy evidence remains available.</p>}
                {repository.agentSignals.length ? (
                  <div className="mt-3 space-y-3">
                    {repository.agentSignals.map((signal) => (
                      <a key={signal.commitSha} href={signal.url} target="_blank" rel="noreferrer" className="block rounded-xl border border-violet-300/15 bg-violet-300/[0.045] p-4 transition hover:border-violet-300/30">
                        <div className="flex items-center justify-between gap-3">
                        <Badge variant="outline" className="border-violet-300/20 bg-violet-300/[0.06] text-[10px] text-violet-200">{signalLabel(signal.classification)}</Badge>
                          <span className="font-mono text-[10px] text-slate-400">SOURCE</span>
                        </div>
                        <p className="mt-3 text-sm font-medium text-slate-200">{signal.message}</p>
                        {signal.changedPaths?.length && <p className="mt-2 break-words font-mono text-xs leading-5 text-violet-200">{signal.changedPaths.join(" · ")}</p>}
                        <p className="mt-2 text-xs leading-5 text-slate-400">{signal.evidence}</p>
                        <p className="mt-3 font-mono text-[11px] text-slate-400">{shortSha(signal.commitSha)} · signature {signal.verified === true ? "verified" : signal.verified === false ? "not verified" : "unknown"}</p>
                      </a>
                    ))}
                  </div>
                ) : (
                  <div className="mt-3 rounded-xl border border-white/[0.08] bg-white/[0.02] p-4">
                    <p className="text-sm text-slate-300">Attribution unknown</p>
                    <p className="mt-1 text-sm leading-6 text-slate-400">No attributed policy change was found in the inspected window. Uninspected commits, candidates, and authorship remain UNKNOWN.</p>
                  </div>
                )}
              </section>

              <Alert className="border-amber-300/15 bg-amber-300/[0.035] text-amber-100">
                <Info className="h-4 w-4" />
                <AlertTitle>What this does not establish</AlertTitle>
                <AlertDescription className="text-amber-100/55">
                  Consistency is not compliance. A verified commit signature authenticates a commit; it does not prove independent review, policy intent, or AI authorship.
                </AlertDescription>
              </Alert>

              <Button asChild variant="outline" className="w-full border-white/10 bg-white/[0.025] text-slate-200 hover:bg-white/[0.06]">
                <a href={`https://github.com/${repository.fullName}`} target="_blank" rel="noreferrer">Open repository</a>
              </Button>
            </div>
          </>
        )}
      </SheetContent>
    </Sheet>
  );
}

function AuditSurface({ audit, onSelect, filter, setFilter }: {
  audit: AuditResult;
  onSelect: (repository: RepoAudit) => void;
  filter: string;
  setFilter: (value: string) => void;
}) {
  const attention = useMemo(
    () => audit.repositories
      .filter((repository) => repository.consistency !== null)
      .sort((a, b) => a.consistency! - b.consistency! || a.evidenceCoverage - b.evidenceCoverage)
      .slice(0, 6),
    [audit.repositories],
  );
  const unknownConsistency = audit.repositories.filter((repository) => repository.consistency === null).length;
  const filtered = audit.repositories.filter((repository) => repository.name.toLowerCase().includes(filter.toLowerCase()));

  return (
    <div className="space-y-5">
      <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <Metric
          icon={Layers3}
          label="Public inventory"
          value={String(audit.inventory.publicRepos).padStart(2, "0")}
          detail={`${audit.inventory.active} active · ${audit.inventory.archived} archived · ${audit.inventory.forks} forks`}
        />
        <Metric
          icon={Network}
          label="Cohort consistency"
          value={audit.scores.consistency === null ? "—" : String(audit.scores.consistency)}
          detail={`Descriptive pairwise agreement across ${audit.sampleSize} repositories; not trust or authorization.`}
          tone="mint"
        />
        <Metric
          icon={Database}
          label="Evidence coverage"
          value={`${audit.scores.evidenceCoverage}%`}
          detail="Unknown inputs stay outside the score; they never become failures."
          tone="amber"
        />
        <Metric
          icon={Bot}
          label="Agent / automation policy commits"
          value={String(agentSignalCount(audit)).padStart(2, "0")}
          detail="Up to 20 recent commits per repo; two attributed file lists across all supported policies."
        />
      </section>

      <section className="grid gap-5 xl:grid-cols-[minmax(0,1.35fr)_minmax(390px,.65fr)]">
        <article className="panel overflow-hidden">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">Drift constellation</p>
              <h2 className="panel-title">Repository coherence map</h2>
            </div>
            <Badge variant="outline" className="border-white/10 bg-white/[0.03] font-mono text-[11px] text-slate-400">PAIRWISE / v1</Badge>
          </div>
          <DriftMap repositories={audit.repositories} onSelect={onSelect} />
        </article>

        <article className="panel overflow-hidden">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">Attention queue</p>
              <h2 className="panel-title">Lowest measured agreement</h2>
            </div>
            <TriangleAlert className="h-4 w-4 text-amber-300/70" aria-hidden="true" />
          </div>
          <div className="divide-y divide-white/[0.07]">
            {attention.map((repo) => (
              <button key={repo.fullName} type="button" onClick={() => onSelect(repo)} className="grid w-full grid-cols-[minmax(0,1fr)_auto] gap-4 px-5 py-4 text-left transition hover:bg-white/[0.025] sm:px-6">
                <div className="min-w-0">
                  <div className="mb-2 flex items-center gap-2">
                    <span className={`status-dot dot-${toneFor(repo.consistency)}`} />
                    <p className="truncate font-mono text-sm font-semibold text-slate-200">{repo.name}</p>
                    <span className="text-xs text-slate-400">{policyPresence(repo)} / {repo.policies.length}</span>
                  </div>
                  <Progress aria-label={`${repo.name} measured pairwise agreement`} value={repo.consistency!} className="h-1 bg-white/[0.07] [&_[data-slot=progress-indicator]]:bg-emerald-300" />
                </div>
                <div className="text-right">
                  <p className="font-mono text-lg font-semibold text-white">{repo.consistency ?? "—"}</p>
                  <p className="text-xs text-slate-400">consistency</p>
                </div>
              </button>
            ))}
          </div>
          <div className="border-t border-white/[0.07] bg-black/20 px-5 py-4 text-xs leading-5 text-slate-400 sm:px-6">
            Lower measured agreement identifies review targets; {unknownConsistency} unknown {unknownConsistency === 1 ? "repository is" : "repositories are"} excluded, never scored as zero. No result proves a policy violation without a declared baseline.
          </div>
        </article>
      </section>

      <section className="panel overflow-hidden">
        <div className="panel-heading flex-wrap">
          <div>
            <p className="eyebrow">{audit.mode === "MEASURED" ? "Exact-source ledger" : audit.mode === "SAMPLE" ? "Sample evidence ledger" : "Partial evidence ledger"}</p>
            <h2 className="panel-title">Sampled repository evidence</h2>
          </div>
          <div className="relative w-full sm:w-64">
            <Search className="absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-400" />
            <Input aria-label="Filter sampled repositories" value={filter} onChange={(event) => setFilter(event.target.value)} placeholder="Filter repositories" className="h-9 border-white/10 bg-black/30 pl-9 text-sm text-slate-200 shadow-none" />
          </div>
        </div>
        <Table>
          <TableHeader>
            <TableRow className="border-white/[0.07] hover:bg-transparent">
              <TableHead className="px-5 font-mono text-[11px] uppercase tracking-wider text-slate-400">Repository</TableHead>
              <TableHead className="font-mono text-[11px] uppercase tracking-wider text-slate-400">Captured head</TableHead>
              <TableHead className="font-mono text-[11px] uppercase tracking-wider text-slate-400">Effective files</TableHead>
              <TableHead className="font-mono text-[11px] uppercase tracking-wider text-slate-400">Consistency</TableHead>
              <TableHead className="font-mono text-[11px] uppercase tracking-wider text-slate-400">Evidence</TableHead>
              <TableHead className="font-mono text-[11px] uppercase tracking-wider text-slate-400">Controls</TableHead>
              <TableHead className="px-5 text-right font-mono text-[11px] uppercase tracking-wider text-slate-400">Signals</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {filtered.map((repository) => (
              <TableRow key={repository.fullName} className="border-white/[0.06] hover:bg-white/[0.025]">
                <TableCell className="px-5 py-4">
                  <button type="button" onClick={() => onSelect(repository)} className="flex items-center gap-2 font-mono font-semibold text-slate-200 hover:text-emerald-200">
                    {repository.name}
                  </button>
                </TableCell>
                <TableCell className="font-mono text-xs text-slate-400">{shortSha(repository.headSha)}</TableCell>
                <TableCell className="text-slate-400">{policyPresence(repository)} / {repository.policies.length}</TableCell>
                <TableCell className="font-mono text-slate-200">{repository.consistency ?? "—"}</TableCell>
                <TableCell className="font-mono text-slate-400">{repository.evidenceCoverage}%</TableCell>
                <TableCell>
                  <span className={deepInspectionBlocked(repository) ? "text-red-300" : repository.protected === true ? "text-emerald-300" : repository.protected === false ? "text-amber-300" : "text-slate-400"}>
                    {deepInspectionBlocked(repository) ? "BLOCKED" : repository.protected === true ? "protected" : repository.protected === false ? "public signal: no" : "unknown"}
                  </span>
                </TableCell>
                <TableCell className="px-5 text-right font-mono text-slate-400">{repository.agentSignals.length}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
        {!filtered.length && <p className="p-8 text-center text-sm text-slate-400">No sampled repository matches that filter.</p>}
      </section>

      <section className="panel overflow-hidden">
        <div className="panel-heading flex-wrap">
          <div>
            <p className="eyebrow">Pinned canonical readback</p>
            <h2 className="panel-title">Current doctrine conflicts stay visible</h2>
          </div>
          <span className="font-mono text-[11px] text-slate-400">MEASURED · {formatObserved(doctrineReadback.observedAt)}</span>
        </div>
        <div className="grid gap-px bg-white/[0.07] lg:grid-cols-3">
          {doctrineReadback.findings.map((finding) => (
            <article key={finding.title} className="bg-[#0b1016] p-5 sm:p-6">
              <Badge variant="outline" className={finding.status === "MEASURED" ? "border-emerald-300/20 bg-emerald-300/[0.06] text-[10px] text-emerald-200" : "border-red-300/20 bg-red-300/[0.06] text-[10px] text-red-200"}>
                {finding.status}
              </Badge>
              <h3 className="mt-4 text-lg font-semibold tracking-[-0.025em] text-white">{finding.title}</h3>
              <p className="mt-3 text-sm leading-6 text-slate-400">{finding.summary}</p>
              <div className="mt-5 flex flex-wrap gap-2">
                {finding.links.map((link) => (
                  <a key={link.url} href={link.url} target="_blank" rel="noreferrer" className="rounded-full border border-white/10 bg-white/[0.025] px-3 py-1.5 font-mono text-[10px] text-slate-300 transition hover:border-emerald-300/25 hover:text-emerald-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-300/60">
                    {link.label}
                  </a>
                ))}
              </div>
            </article>
          ))}
        </div>
        <div className="border-t border-white/[0.07] bg-black/20 px-5 py-4 font-mono text-[10px] text-slate-400 sm:px-6">
          GitHub public GET readback · .github {doctrineReadback.organizationHead.slice(0, 12)} · source evidence only, not deployment or authorization
        </div>
      </section>

      {audit.publicInventory && (
        <section className="panel overflow-hidden">
          <div className="panel-heading flex-wrap">
            <div><p className="eyebrow">Public inventory</p><h2 className="panel-title">Every listed repository, with deep coverage marked</h2></div>
            <span className="text-sm text-slate-400">{audit.publicInventory.filter((repository) => repository.fullName.toLowerCase().includes(filter.toLowerCase())).length} match the repository filter</span>
          </div>
          <div className="grid gap-px bg-white/[0.07] sm:grid-cols-2 xl:grid-cols-3">
            {audit.publicInventory.filter((repository) => repository.fullName.toLowerCase().includes(filter.toLowerCase())).slice(0, 30).map((repository) => (
              <div key={repository.fullName} className="flex min-w-0 items-center justify-between gap-3 bg-[#0b1016] p-4">
                <a href={`https://github.com/${repository.fullName}`} target="_blank" rel="noreferrer" className="truncate text-sm text-slate-200 hover:text-emerald-200">{repository.fullName.split("/")[1]}</a>
                <span className="shrink-0 text-xs text-slate-400">{repository.archived ? "archived" : repository.fork ? "fork" : repository.disabled ? "disabled" : audit.repositories.some((sample) => sample.fullName === repository.fullName) ? "deep inspection" : "inventory only"}</span>
              </div>
            ))}
          </div>
          <p className="border-t border-white/[0.07] px-5 py-4 text-sm text-slate-400">Showing up to 30 matches. Use the repository filter to find others. The export retains the complete paginated inventory; inventory-only entries have no deep policy score.</p>
        </section>
      )}

      <section className="grid gap-3 md:grid-cols-3">
        {audit.limitations.map((limitation, index) => (
          <div key={limitation} className="rounded-xl border border-white/[0.07] bg-white/[0.018] p-4">
            <p className="font-mono text-[11px] text-slate-400">BOUNDARY {String(index + 1).padStart(2, "0")}</p>
            <p className="mt-2 text-sm leading-6 text-slate-400">{limitation}</p>
          </div>
        ))}
      </section>
    </div>
  );
}

function ResearchBrief() {
  return (
    <div className="space-y-5">
      <section className="grid gap-5 lg:grid-cols-[.78fr_1.22fr]">
        <article className="panel p-6 sm:p-8">
          <div className="flex items-center gap-2 text-emerald-300/80">
            <Fingerprint className="h-4 w-4" />
            <p className="eyebrow !text-emerald-300/80">Research synthesis · 2026-10-03</p>
          </div>
          <h2 className="mt-5 text-balance text-4xl font-semibold leading-[1.02] tracking-[-0.055em] text-white">Three layers. Three outputs. No honest single winner.</h2>
          <p className="mt-6 leading-7 text-slate-400">
            “Agentic curation” spans evolutionary training-data search, scaffolded research agents, and provenance-rich scientific knowledge modeling. They can reinforce one another, but they do not optimize the same artifact.
          </p>
          <div className="mt-8 rounded-xl border border-emerald-300/15 bg-emerald-300/[0.045] p-4">
            <p className="font-mono text-xs uppercase tracking-[.14em] text-emerald-300/80">Conditional efficiency verdict</p>
            <p className="mt-3 text-sm leading-6 text-slate-300">
              CurateEvo reports a curation-overhead gain. Curation-Bench shows that method-grounded search can widen policy exploration. GO-CAM emphasizes structured provenance and expert oversight. These are separate evidence surfaces, not a head-to-head ranking.
            </p>
          </div>
        </article>
        <div className="grid gap-3 sm:grid-cols-3">
          {methods.map((method, index) => {
            const icons = [Braces, Bot, Activity];
            const Icon = icons[index];
            return (
              <article key={method.key} className="method-card group">
                <div className="flex items-center justify-between">
                  <Icon className="h-5 w-5 text-emerald-300" />
                  <span className="font-mono text-[10px] text-slate-400">0{index + 1}</span>
                </div>
                <h3 className="mt-8 text-xl font-semibold tracking-[-0.03em] text-white">{method.name}</h3>
                <p className="mt-2 font-mono text-xs text-emerald-300/65">{method.kicker}</p>
                <p className="mt-5 text-sm leading-6 text-slate-400">{method.definition}</p>
                <div className="mt-6 h-px bg-gradient-to-r from-emerald-300/50 to-transparent" />
              </article>
            );
          })}
        </div>
      </section>

      <section className="panel overflow-hidden">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">Cross-framework matrix</p>
            <h2 className="panel-title">Efficiency means different things here</h2>
          </div>
          <Badge variant="outline" className="border-amber-300/20 bg-amber-300/[0.05] text-[10px] text-amber-200">NO HEAD-TO-HEAD STUDY</Badge>
        </div>
        <Table>
          <TableHeader>
            <TableRow className="border-white/[0.07] hover:bg-transparent">
              <TableHead className="min-w-40 px-5 font-mono text-[11px] uppercase tracking-wider text-slate-400">Dimension</TableHead>
              <TableHead className="min-w-64 font-mono text-[11px] uppercase tracking-wider text-emerald-300/70">CurateEvo</TableHead>
              <TableHead className="min-w-64 font-mono text-[11px] uppercase tracking-wider text-sky-300/70">Scaffolded agents</TableHead>
              <TableHead className="min-w-64 px-5 font-mono text-[11px] uppercase tracking-wider text-violet-300/70">GO-CAM builders</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {comparisonRows.map((row) => (
              <TableRow key={row.dimension} className="border-white/[0.06] hover:bg-white/[0.018]">
                <TableCell className="px-5 py-5 align-top font-medium text-slate-200">{row.dimension}</TableCell>
                <TableCell className="max-w-sm whitespace-normal py-5 align-top text-sm leading-6 text-slate-400">{row.curateEvo}</TableCell>
                <TableCell className="max-w-sm whitespace-normal py-5 align-top text-sm leading-6 text-slate-400">{row.scaffolded}</TableCell>
                <TableCell className="max-w-sm whitespace-normal px-5 py-5 align-top text-sm leading-6 text-slate-400">{row.gocam}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </section>

      <section className="grid gap-4 lg:grid-cols-3">
        {methods.map((method, index) => (
          <article key={method.key} className="panel p-6">
            <div className="flex items-center justify-between gap-3">
              <p className="eyebrow">Evidence readout 0{index + 1}</p>
              <Badge variant="outline" className="border-white/10 bg-white/[0.025] text-[10px] text-slate-400">REPORTED</Badge>
            </div>
            <h3 className="mt-4 text-lg font-semibold text-white">{method.name}</h3>
            <p className="mt-4 text-sm leading-6 text-slate-300">{method.evidence}</p>
            <div className="my-5 h-px bg-white/[0.07]" />
            <p className="flex gap-2 text-xs leading-5 text-amber-100/55"><AlertTriangle className="mt-0.5 h-3.5 w-3.5 flex-none" />{method.limitation}</p>
          </article>
        ))}
      </section>

      <section className="grid gap-5 lg:grid-cols-[1.1fr_.9fr]">
        <article className="panel p-6 sm:p-8">
          <div className="flex items-center gap-2 text-violet-300">
            <Sparkles className="h-4 w-4" />
            <p className="eyebrow !text-violet-300/80">MODELED · frontier design hypothesis</p>
          </div>
          <h2 className="mt-4 text-3xl font-semibold tracking-[-0.045em] text-white">{frontierHypothesis.title}</h2>
          <p className="mt-5 leading-7 text-slate-400">{frontierHypothesis.body}</p>
          <p className="mt-5 rounded-xl border border-violet-300/15 bg-violet-300/[0.04] p-4 text-sm leading-6 text-violet-100/60">{frontierHypothesis.caveat}</p>
        </article>
        <article className="panel p-6 sm:p-8">
          <p className="eyebrow">Evidence discipline</p>
          <h2 className="mt-4 text-2xl font-semibold tracking-[-0.04em] text-white">REPORTED vs. MODELED</h2>
          <div className="mt-6 space-y-5">
            <div className="flex gap-3">
              <Check className="mt-1 h-4 w-4 flex-none text-emerald-300" />
              <div><p className="text-sm font-medium text-slate-200">REPORTED</p><p className="mt-1 text-sm leading-6 text-slate-400">Authors’ paper-reported scores, token overhead, wall time, participant counts, tool calls, and workflow failures; not independently replayed here.</p></div>
            </div>
            <div className="flex gap-3">
              <Orbit className="mt-1 h-4 w-4 flex-none text-violet-300" />
              <div><p className="text-sm font-medium text-slate-200">MODELED</p><p className="mt-1 text-sm leading-6 text-slate-400">Which method may fit a new use case, how they might compose, and whether provenance gains could outweigh added validation cost.</p></div>
            </div>
          </div>
        </article>
      </section>

      <section className="panel overflow-hidden">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">Primary record</p>
            <h2 className="panel-title">Papers, official documentation, and source code</h2>
          </div>
          <span className="font-mono text-xs text-slate-400">{sources.length} sources</span>
        </div>
        <div className="grid gap-px bg-white/[0.07] sm:grid-cols-2 lg:grid-cols-3">
          {sources.map((source) => (
            <a key={source.url} href={source.url} target="_blank" rel="noreferrer" className="flex min-h-24 items-center justify-between gap-4 bg-[#0b1016] p-5 transition hover:bg-[#101820]">
              <div>
                <p className="text-sm font-medium text-slate-200">{source.label}</p>
                <p className="mt-2 font-mono text-[10px] uppercase tracking-wider text-slate-400">{source.kind}</p>
              </div>
              <span className="font-mono text-[10px] text-slate-400">OPEN</span>
            </a>
          ))}
        </div>
      </section>
    </div>
  );
}

function ScoringModel({ audit, onExport, receiptSha }: { audit: AuditResult; onExport: () => void; receiptSha: string | null }) {
  const outcomes = [
    ["EXACT", "Same Git blob as the declared canonical object", "0.00"],
    ["EQUIVALENT", "Same deterministic operational fingerprint", "0.02"],
    ["APPROVED VARIANT", "Exact digest matches a non-expired declared exception", "0.00"],
    ["RULE-PRESERVING", "Text differs; all declared machine-checkable rules pass", "0.20"],
    ["REVIEW DRIFT", "Substantive difference; semantics not safely classified", "0.50"],
    ["REQUIRED MISSING", "Complete evidence proves an applicable file is absent", "1.00"],
    ["UNKNOWN", "Evidence incomplete, rate-limited, oversized, or unsupported", "—"],
  ];

  return (
    <div className="space-y-5">
      <section className="grid gap-5 lg:grid-cols-[.82fr_1.18fr]">
        <article className="panel p-6 sm:p-8">
          <p className="eyebrow">Explainable by construction</p>
          <h2 className="mt-4 text-4xl font-semibold leading-[1.02] tracking-[-0.055em] text-white">Three numbers. Never one magic health score.</h2>
          <p className="mt-6 leading-7 text-slate-400">
            A repository can be perfectly consistent with its peers and still violate canonical policy. This descriptive percentage is not a trust score, so it does not override the 0.97 trust ceiling or authorize action. Alignment, consistency, and evidence coverage stay separate.
          </p>
          <div className="mt-7 space-y-3">
            {[
              ["Policy alignment", "Conformity to an explicit, pinned baseline. Suppressed here because no manifest was supplied."],
              ["Cohort consistency", "Pairwise agreement among observed operational fingerprints."],
              ["Evidence coverage", "Weighted fraction of the applicable surface conclusively observed."],
            ].map(([title, copy], index) => (
              <div key={title} className="flex gap-4 rounded-xl border border-white/[0.08] bg-white/[0.02] p-4">
                <span className="font-mono text-xs text-emerald-300/70">0{index + 1}</span>
                <div><p className="text-sm font-medium text-slate-200">{title}</p><p className="mt-1 text-sm leading-6 text-slate-400">{copy}</p></div>
              </div>
            ))}
          </div>
        </article>
        <article className="panel overflow-hidden">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">Current evidence boundary</p>
              <h2 className="panel-title">Reconstructable score state</h2>
            </div>
            <Badge variant="outline" className="border-amber-300/20 bg-amber-300/[0.05] text-[10px] text-amber-200">NO DECLARED BASELINE</Badge>
          </div>
          <div className="grid gap-px bg-white/[0.07] sm:grid-cols-3">
            <div className="bg-[#0b1016] p-6"><p className="eyebrow">Alignment</p><p className="mt-4 font-mono text-3xl text-slate-400">—</p><p className="mt-3 text-xs leading-5 text-slate-400">Intentionally suppressed.</p></div>
            <div className="bg-[#0b1016] p-6"><p className="eyebrow">Consistency</p><p className="mt-4 font-mono text-3xl text-emerald-300">{audit.scores.consistency ?? "—"}</p><p className="mt-3 text-xs leading-5 text-slate-400">Sampled pair agreement.</p></div>
            <div className="bg-[#0b1016] p-6"><p className="eyebrow">Coverage</p><p className="mt-4 font-mono text-3xl text-amber-200">{audit.scores.evidenceCoverage}%</p><p className="mt-3 text-xs leading-5 text-slate-400">Unknowns excluded.</p></div>
          </div>
          <div className="p-6">
            <p className="eyebrow">Pairwise consistency</p>
            <pre className="mt-4 overflow-x-auto rounded-xl border border-white/[0.08] bg-black/30 p-4 font-mono text-xs leading-6 text-slate-400">{`Uₒ = Σₖ nₒₖ(nₒₖ − 1) / Nₒ(Nₒ − 1)\n\nConsistency = 100 × Σ(wₒ × Uₒ) / Σwₒ`}</pre>
            <p className="mt-4 text-sm leading-6 text-slate-400">A cohort can be consistently missing a required control. That yields high consistency and low alignment—the contrast is the signal.</p>
          </div>
        </article>
      </section>

      <section className="panel overflow-hidden">
        <div className="panel-heading">
          <div><p className="eyebrow">MODELED · future contract</p><h2 className="panel-title">Penalty model for a future pinned manifest</h2></div>
          <span className="font-mono text-xs text-slate-400">unknown ≠ failure</span>
        </div>
        <div className="grid gap-px bg-white/[0.07] md:grid-cols-2 xl:grid-cols-4">
          {outcomes.map(([name, description, penalty]) => (
            <div key={name} className="min-h-40 bg-[#0b1016] p-5">
              <div className="flex items-center justify-between gap-3"><p className="font-mono text-xs text-slate-300">{name}</p><span className="font-mono text-xs text-emerald-300/70">{penalty}</span></div>
              <p className="mt-5 text-sm leading-6 text-slate-400">{description}</p>
            </div>
          ))}
        </div>
      </section>

      <section className="grid gap-5 lg:grid-cols-2">
        <article className="panel p-6 sm:p-8">
          <div className="flex items-center gap-2"><Bot className="h-4 w-4 text-violet-300" /><p className="eyebrow !text-violet-300/75">Attribution ladder</p></div>
          <h2 className="mt-4 text-2xl font-semibold tracking-[-0.04em] text-white">The account is not the authoring process.</h2>
          <div className="mt-6 space-y-4">
            {[
              ["Automation actor observed", "GitHub attributes the action to a Bot/App identity. This does not prove an AI system wrote the policy text."],
              ["Agent assistance attested", "A structured statement is bound to the commit and verified against a configured trusted identity."],
              ["Agent assistance declared", "The commit or PR states that an agent assisted; the dashboard has not independently verified it."],
              ["Attribution unknown", "Public metadata does not establish whether a person, script, or AI drafted the change."],
            ].map(([title, copy]) => (
              <div key={title} className="border-l border-white/10 pl-4"><p className="text-sm font-medium text-slate-200">{title}</p><p className="mt-1 text-sm leading-6 text-slate-400">{copy}</p></div>
            ))}
          </div>
        </article>
        <article className="panel p-6 sm:p-8">
          <div className="flex items-center gap-2"><FileCheck2 className="h-4 w-4 text-emerald-300" /><p className="eyebrow !text-emerald-300/75">Local evidence receipt</p></div>
          <h2 className="mt-4 text-2xl font-semibold tracking-[-0.04em] text-white">Bind this observation to a digest.</h2>
          <p className="mt-5 text-sm leading-6 text-slate-400">The export contains the scan window, {audit.mode === "SAMPLE" ? "recorded abbreviated head prefixes" : "full repository heads for successful live inspections"}, policy states, derivations, limitations, and a canonical JSON SHA-256. It is not a GitHub attestation or third-party signature.</p>
          <div className="mt-6 rounded-xl border border-white/[0.08] bg-black/25 p-4">
            <p className="eyebrow">Current source mode</p>
            <p className="mt-2 font-mono text-sm text-slate-200">{audit.mode} · {formatObserved(audit.observedAt)}</p>
            {receiptSha && <p className="mt-3 break-all font-mono text-[10px] leading-5 text-emerald-300/65">sha256:{receiptSha}</p>}
          </div>
          <Button onClick={onExport} className="mt-5 h-11 w-full bg-emerald-300 font-semibold text-[#04110e] hover:bg-emerald-200"><FileCheck2 className="h-4 w-4" /> Export receipt</Button>
        </article>
      </section>
    </div>
  );
}

function ChangeComparison({ audit, baseline, onBaseline }: { audit: AuditResult; baseline: VerifiedBaseline | null; onBaseline: (value: VerifiedBaseline | null) => void }) {
  const [importError, setImportError] = useState<string | null>(null);
  const comparison = useMemo(() => {
    if (!baseline) return null;
    try { return { result: compareAudits(baseline.audit, audit), error: null }; }
    catch (error) { return { result: null, error: error instanceof Error ? error.message : "Comparison is unavailable." }; }
  }, [audit, baseline]);
  const result = comparison?.result;
  const changes = result?.deltas.filter((delta) => ["ADDED", "REMOVED", "CHANGED"].includes(delta.change)) ?? [];
  const unknown = result?.deltas.filter((delta) => delta.change === "UNKNOWN").length ?? 0;
  const loadBaseline = async (file: File | undefined) => {
    if (!file) return;
    setImportError(null);
    try {
      if (file.size > 2_000_000) throw new Error("Choose a Curation Atlas JSON receipt smaller than 2 MB.");
      onBaseline(await verifyImportedReceipt(await file.text()));
    } catch (error) { setImportError(error instanceof Error ? error.message : "The receipt could not be read."); }
  };
  return (
    <div className="space-y-5">
      <section className="panel p-5 sm:p-7">
        <div className="flex flex-wrap items-start justify-between gap-5">
          <div className="max-w-2xl"><p className="eyebrow">Changes over time</p><h2 className="mt-2 text-2xl font-semibold text-white">Compare a previous receipt with this audit</h2><p className="mt-3 text-base leading-7 text-slate-400">Load a prior Curation Atlas export, then scan the same organization. The comparison follows exact policy fingerprints in overlapping repositories. Your file is read locally in this page.</p></div>
          {baseline && <Button variant="outline" className="border-white/15 bg-white/[0.025] text-slate-200" onClick={() => { onBaseline(null); setImportError(null); }}>Clear baseline</Button>}
        </div>
        <label htmlFor="baseline-receipt" className="mt-6 block text-sm font-medium text-slate-200">Previous JSON receipt · maximum 2 MB</label>
        <Input id="baseline-receipt" type="file" accept=".json,application/json" className="mt-2 h-12 border-white/15 bg-black/25 text-sm text-slate-200" onChange={(event) => { void loadBaseline(event.target.files?.[0]); event.target.value = ""; }} />
        {baseline && <div className="mt-5 rounded-xl border border-emerald-300/20 bg-emerald-300/[0.04] p-4"><p className="text-sm text-emerald-200">Digest matches the file · {baseline.audit.orgLogin} · {formatObserved(baseline.audit.observedAt)}</p><p className="mt-2 text-sm leading-6 text-slate-400">This checks the included digest. The unsigned file does not establish its author or GitHub origin. The baseline stays in this page until you clear it or reload.</p></div>}
        {(importError || comparison?.error) && <Alert className="mt-5 border-amber-300/20 bg-amber-300/[0.05] text-amber-100"><AlertTriangle className="h-4 w-4" /><AlertTitle>Comparison unavailable</AlertTitle><AlertDescription className="text-sm text-amber-100/80">{importError ?? comparison?.error}</AlertDescription></Alert>}
      </section>
      {result && <>
        <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
          <Metric icon={Layers3} label="Overlapping repositories" value={String(result.overlapCount)} detail="Only repositories present in both deep inspection cohorts are compared." />
          <Metric icon={GitBranch} label="Different captured revisions" value={String(result.changedRevisionCount)} detail="Different full commit SHAs; ancestry and rollback are not inferred." />
          <Metric icon={FileCheck2} label="Policy changes observed" value={String(changes.length)} detail="Added, removed, or changed effective policies with complete source evidence." tone="amber" />
          <Metric icon={Info} label="Unknown policy comparisons" value={String(unknown)} detail="Missing fingerprints, SAMPLE data, or incomplete source evidence stays UNKNOWN." />
        </section>
        <section className="panel overflow-hidden"><div className="panel-heading"><div><p className="eyebrow">Effective policy transitions</p><h2 className="panel-title">{changes.length ? "Observed changes" : "No changes established by comparable evidence"}</h2></div></div>
          {changes.map((delta) => <article key={delta.fullName + delta.key} className="border-t border-white/[0.07] p-5"><div className="flex flex-wrap items-center gap-3"><Badge variant="outline" className="border-amber-300/25 text-xs text-amber-200">{delta.change}</Badge><p className="font-mono text-sm text-white">{delta.fullName}</p><p className="text-sm text-slate-300">{delta.label}</p></div><p className="mt-3 text-sm leading-6 text-slate-400">{delta.reason}</p><div className="mt-3 grid gap-3 md:grid-cols-2">{[["Before", delta.before], ["After", delta.after]].map(([label, value]) => { const policy = value as typeof delta.before; return <div key={String(label)} className="rounded-lg bg-black/25 p-3"><p className="text-xs text-slate-400">{String(label)} · {policy.state}</p><p className="mt-1 break-words font-mono text-sm text-slate-200">{policy.path ?? "No effective path"}</p><p className="mt-1 break-words text-xs text-slate-400">{policy.sourceRepo ?? "repository-local"} · {policy.blobSha?.startsWith("set:") ? "workflow set fingerprint" : policy.blobSha ?? "no blob"}</p></div>; })}</div></article>)}
          <p className="border-t border-white/[0.07] p-5 text-sm leading-6 text-slate-400">{result.deltas.filter((delta) => delta.change === "UNCHANGED").length} comparable policy observations match; {unknown} remain UNKNOWN. A matching fingerprint establishes the observed bytes or set, while policy compliance requires a declared baseline.</p>
        </section>
        <section className="panel p-5"><h3 className="text-lg font-semibold text-white">Inspection cohort changes</h3><p className="mt-3 text-sm leading-6 text-slate-400">{result.enteredCohort.length} entered and {result.leftCohort.length} left the sampled cohort. This describes inspection coverage; repository creation or deletion is not established.</p><p className="mt-3 break-words text-sm text-slate-300">Entered: {result.enteredCohort.join(", ") || "none"}</p><p className="mt-2 break-words text-sm text-slate-300">Left: {result.leftCohort.join(", ") || "none"}</p><p className="mt-4 text-sm leading-6 text-slate-400">Cohort consistency scores are not compared because the peer distribution can change between scans. Inherited policy comparisons require their .github source to be pinned in both receipts.</p></section>
      </>}
    </div>
  );
}

export default function Home() {
  const [audit, setAudit] = useState<AuditResult>(SNAPSHOT_RESULT);
  const [org, setOrg] = useState("szl-holdings");
  const [sampleSize, setSampleSize] = useState(6);
  const [running, setRunning] = useState(false);
  const [progress, setProgress] = useState<ScanProgress | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [selectedRepo, setSelectedRepo] = useState<RepoAudit | null>(null);
  const [filter, setFilter] = useState("");
  const [receiptSha, setReceiptSha] = useState<string | null>(null);
  const [rateRemaining, setRateRemaining] = useState<number | null>(null);
  const [rateLimit, setRateLimit] = useState<number | null>(null);
  const [baseline, setBaseline] = useState<VerifiedBaseline | null>(null);
  const scanInFlight = useRef(false);

  const runAudit = useCallback(async (requestedOrg = org, requestedSampleSize = sampleSize) => {
    if (scanInFlight.current) throw new Error("An audit is already running. Wait for it to finish before starting another.");
    scanInFlight.current = true;
    setRunning(true);
    setError(null);
    setReceiptSha(null);
    setRateRemaining(null);
    setRateLimit(null);
    setProgress({ message: "Starting live audit", completed: 0, total: 1 });
    setOrg(requestedOrg);
    setSampleSize(requestedSampleSize);
    try {
      const result = await scanOrganization(
        requestedOrg,
        requestedSampleSize,
        (message, completed, total) => setProgress({ message, completed, total }),
        (rate) => {
          setRateRemaining(rate.remaining);
          setRateLimit(rate.limit);
        },
      );
      setAudit(result);
      setOrg(result.org.login);
      const failedCount = result.repositories.filter(deepInspectionBlocked).length;
      setProgress({
        message: result.mode === "BLOCKED"
          ? `Partial evidence retained · ${failedCount} deep inspection${failedCount === 1 ? "" : "s"} unavailable or incomplete`
          : "Live audit complete",
        completed: result.sampleSize,
        total: result.sampleSize,
      });
      return result;
    } catch (caught) {
      const message = caught instanceof Error ? caught.message : "The live audit could not be completed.";
      setError(message);
      throw caught instanceof Error ? caught : new Error(message);
    } finally {
      scanInFlight.current = false;
      setRunning(false);
    }
  }, [org, sampleSize]);

  useEffect(() => {
    const context = document.modelContext;
    if (!context?.registerTool) return;
    const lifecycle = new AbortController();
    const register = async () => {
      await context.registerTool(
        {
          name: "get_current_curation_audit",
          title: "Read current curation audit",
          description: "Read the GitHub organization audit currently visible in Curation Atlas without starting a new scan.",
          inputSchema: { type: "object", properties: {}, additionalProperties: false },
          annotations: { readOnlyHint: true, untrustedContentHint: true },
          execute() {
            return {
              mode: audit.mode,
              organization: audit.org.login,
              observedAt: audit.observedAt,
              publicRepositoryCount: audit.inventory.publicRepos,
              deepSampleSize: audit.sampleSize,
              cohortConsistency: audit.scores.consistency,
              evidenceCoverage: audit.scores.evidenceCoverage,
              alignment: audit.scores.alignment,
              limitations: audit.limitations,
            };
          },
        },
        { signal: lifecycle.signal },
      );
      await context.registerTool(
        {
          name: "run_public_github_curation_audit",
          title: "Run public GitHub curation audit",
          description: "Run the same read-only public GitHub organization audit as the visible Run live audit control and update the dashboard when complete.",
          inputSchema: {
            type: "object",
            properties: {
              organization: { type: "string", description: "Public GitHub organization handle." },
              deepSampleSize: { type: "integer", enum: [4, 6, 8], description: "Number of active public repositories to inspect deeply." },
            },
            required: ["organization"],
            additionalProperties: false,
          },
          annotations: { readOnlyHint: true, untrustedContentHint: true },
          async execute(input) {
            if (!input || typeof input !== "object") throw new Error("Expected an object input.");
            const values = input as { organization?: unknown; deepSampleSize?: unknown };
            if (typeof values.organization !== "string" || !values.organization.trim()) {
              throw new Error("organization must be a non-empty GitHub handle.");
            }
            const requestedSize = values.deepSampleSize === undefined ? sampleSize : Number(values.deepSampleSize);
            if (![4, 6, 8].includes(requestedSize)) throw new Error("deepSampleSize must be 4, 6, or 8.");
            const result = await runAudit(values.organization, requestedSize);
            return {
              mode: result.mode,
              organization: result.org.login,
              observedAt: result.observedAt,
              publicRepositoryCount: result.inventory.publicRepos,
              deepSampleSize: result.sampleSize,
              cohortConsistency: result.scores.consistency,
              evidenceCoverage: result.scores.evidenceCoverage,
              alignment: result.scores.alignment,
              requestBudgetRemaining: result.rate.remaining,
              limitations: result.limitations,
            };
          },
        },
        { signal: lifecycle.signal },
      );
    };
    void register().catch(() => {
      // WebMCP is optional; the visible interface remains the source of truth.
    });
    return () => lifecycle.abort();
  }, [audit, runAudit, sampleSize]);

  const exportReceipt = async () => {
    const receipt = await createReceipt(audit);
    setReceiptSha(receipt.receiptSha256);
    const blob = new Blob([JSON.stringify(receipt, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `curation-atlas-${audit.org.login}-${audit.observedAt.slice(0, 10)}.json`;
    anchor.click();
    URL.revokeObjectURL(url);
  };

  const modeClass = audit.mode === "MEASURED"
    ? "border-emerald-300/20 bg-emerald-300/[0.07] text-emerald-200"
    : audit.mode === "BLOCKED" || audit.mode === "UNAVAILABLE"
      ? "border-red-300/20 bg-red-300/[0.07] text-red-200"
      : "border-amber-300/20 bg-amber-300/[0.07] text-amber-200";
  const progressValue = progress && progress.total ? Math.round((progress.completed / progress.total) * 100) : running ? 8 : 100;

  return (
    <main className="min-h-screen overflow-x-hidden bg-[#070a0e] text-slate-100">
      <div className="scanline" aria-hidden="true" />
      <header className="sticky top-0 z-40 border-b border-white/[0.08] bg-[#070a0e]/90 backdrop-blur-xl">
        <div className="mx-auto flex h-16 max-w-[1540px] items-center justify-between px-4 sm:px-7">
          <div className="flex min-w-0 items-center gap-3">
            <div className="brand-mark" aria-hidden="true"><Radar className="h-4 w-4" /></div>
            <div className="min-w-0">
              <p className="truncate text-[15px] font-semibold tracking-[-0.02em] text-white">Curation Atlas</p>
              <p className="hidden text-xs text-slate-400 sm:block">organization policy intelligence</p>
            </div>
          </div>
          <div className="flex items-center gap-2 sm:gap-3">
            <Badge variant="outline" className={`${modeClass} px-2.5 py-1 text-[11px] font-medium`}><CircleDot className="h-3 w-3" />{audit.mode}</Badge>
            <div className="hidden h-6 w-px bg-white/10 sm:block" />
            <span className="hidden font-mono text-xs text-slate-400 sm:inline">public · read-only · evidence-first</span>
          </div>
        </div>
      </header>

      <div className="mx-auto max-w-[1540px] px-4 pb-16 pt-7 sm:px-7 sm:pt-9">
        <section className="mb-7 grid gap-5 xl:grid-cols-[minmax(0,1fr)_auto] xl:items-end">
          <div>
            <div className="mb-3 flex items-center gap-2 font-mono text-xs uppercase tracking-[0.18em] text-emerald-300/80">
              <Fingerprint className="h-3.5 w-3.5" /> Evidence surface 01
            </div>
            <h1 className="max-w-4xl text-balance text-3xl font-semibold leading-tight tracking-[-0.04em] text-white sm:text-4xl">
              Inspect policy drift and recent changes.
            </h1>
          </div>
          <div className="w-full rounded-2xl border border-white/[0.09] bg-white/[0.035] p-2 xl:w-[590px]">
            <div className="flex flex-col gap-2 sm:flex-row">
              <div className="relative flex-1">
                <label htmlFor="org" className="sr-only">GitHub organization</label>
                <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" aria-hidden="true" />
                <Input id="org" value={org} onChange={(event) => setOrg(event.target.value)} onKeyDown={(event) => { if (event.key === "Enter" && !running) void runAudit().catch(() => undefined); }} className="h-11 border-white/10 bg-black/30 pl-9 font-mono text-sm text-white shadow-none focus-visible:border-emerald-300/60 focus-visible:ring-emerald-300/15" />
              </div>
              <NativeSelect value={String(sampleSize)} onChange={(event) => setSampleSize(Number(event.target.value))} aria-label="Deep audit sample size" className="h-11 w-full border-white/10 bg-black/30 text-slate-300 sm:w-[112px]">
                <NativeSelectOption value="4">4 deep</NativeSelectOption>
                <NativeSelectOption value="6">6 deep</NativeSelectOption>
                <NativeSelectOption value="8">8 deep</NativeSelectOption>
              </NativeSelect>
              <Button onClick={() => void runAudit().catch(() => undefined)} disabled={running} className="h-11 bg-emerald-300 px-5 font-semibold text-[#04110e] hover:bg-emerald-200">
                <RefreshCw className={`h-4 w-4 ${running ? "animate-spin" : ""}`} /> {running ? "Scanning" : "Run live audit"}
              </Button>
            </div>
            {(running || progress) && (
              <div className="px-2 pb-1 pt-3" aria-live="polite">
                <div className="mb-2 flex items-center justify-between gap-4 font-mono text-[10px] text-slate-400">
                  <span className="truncate">{progress?.message ?? "Starting live audit"}</span>
                  <span>{progressValue}%</span>
                </div>
                <Progress aria-label="Live audit progress" value={progressValue} className="h-1 bg-white/[0.06] [&_[data-slot=progress-indicator]]:bg-emerald-300" />
              </div>
            )}
          </div>
        </section>

        {error && (
          <Alert variant="destructive" className="mb-5 border-red-300/15 bg-red-300/[0.04] text-red-200">
            <AlertTriangle className="h-4 w-4" />
            <AlertTitle>Live audit paused</AlertTitle>
            <AlertDescription className="text-red-100/60">{error} The existing {audit.mode.toLowerCase()} evidence remains visible and unchanged.</AlertDescription>
          </Alert>
        )}

        {audit.mode === "BLOCKED" && (
          <Alert className="mb-5 border-amber-300/20 bg-amber-300/[0.04] text-amber-100">
            <AlertTriangle className="h-4 w-4" />
            <AlertTitle>Partial live evidence retained · BLOCKED</AlertTitle>
            <AlertDescription className="text-amber-100/65">
              {audit.repositories.filter(deepInspectionBlocked).length} deep repository {audit.repositories.filter(deepInspectionBlocked).length === 1 ? "inspection was" : "inspections were"} unavailable or incomplete. Unknown inputs are excluded from scores; inspect the boundary cards and repository details before acting.
            </AlertDescription>
          </Alert>
        )}

        <Tabs defaultValue="audit" className="gap-6">
          <div className="flex flex-col gap-4 border-b border-white/[0.08] pb-4 lg:flex-row lg:items-center lg:justify-between">
            <TabsList variant="line" className="h-10 max-w-full justify-start gap-4 overflow-x-auto p-0">
              <TabsTrigger value="audit" className="px-0 text-sm text-slate-400 data-[state=active]:text-white">Audit surface</TabsTrigger>
              <TabsTrigger value="changes" className="px-0 text-sm text-slate-400 data-[state=active]:text-white">Changes over time</TabsTrigger>
              <TabsTrigger value="research" className="px-0 text-sm text-slate-400 data-[state=active]:text-white">Research brief</TabsTrigger>
              <TabsTrigger value="method" className="px-0 text-sm text-slate-400 data-[state=active]:text-white">Scoring model</TabsTrigger>
            </TabsList>
            <div className="flex flex-wrap items-center gap-x-4 gap-y-2 font-mono text-[11px] text-slate-400">
              <span><Clock3 className="mr-1.5 inline h-3 w-3" />{formatObserved(audit.observedAt)}</span>
              <span><GitBranch className="mr-1.5 inline h-3 w-3" />{audit.sampleSize} / {audit.inventory.publicRepos} deep</span>
              {rateRemaining !== null && <span><Database className="mr-1.5 inline h-3 w-3" />{rateRemaining} / {rateLimit ?? 60} requests left</span>}
            </div>
          </div>

          <TabsContent value="audit"><AuditSurface audit={audit} onSelect={setSelectedRepo} filter={filter} setFilter={setFilter} /></TabsContent>
          <TabsContent value="changes"><ChangeComparison audit={audit} baseline={baseline} onBaseline={setBaseline} /></TabsContent>
          <TabsContent value="research"><ResearchBrief /></TabsContent>
          <TabsContent value="method"><ScoringModel audit={audit} onExport={() => void exportReceipt()} receiptSha={receiptSha} /></TabsContent>
        </Tabs>
      </div>

      <RepoInspector repository={selectedRepo} open={Boolean(selectedRepo)} onOpenChange={(open) => { if (!open) setSelectedRepo(null); }} />
    </main>
  );
}
