# Leader-Study Upgrade Plan - W27 loop-5 - 2026-11-23

Status: PROPOSE-ONLY DRAFT - DO NOT MERGE. Owner-gated: merging requires governing approval and the estate signature-wall owner unlock.

Repo: curation-atlas - Public-source, evidence-bounded GitHub curation audit and research dashboard

Frame: OUROBOROS loop-5 leader study. Governing seat: Kimi kimi-k3.1-pro (json_ok, think off). Advisory seats: Astra/Sol/Claude community rails (provenance unverified, advisory only). Leader evidence web-verified 2026-11-23.

## Leader moats to absorb
- OpenSSF Scorecard: Automated heuristic security checks for open-source projects, scoring 0-10 per check with explicit false-positive/false-negative disclosure and alignment to Security Baseline. Moat: Opinionated, continuously maintained check heuristics plus honest uncertainty reporting and broad ecosystem adoption.
- GitHub CodeQL: Semantic code analysis that treats code as queryable data to find vulnerabilities and variants across supported languages. Moat: Deep semantic program analysis, a large maintained query ecosystem, and native GitHub code-scanning integration.
- Semgrep: Fast, syntax-aware static analysis with customizable rules for security, correctness, and organizational coding policies. Moat: Accessible rule authoring, lightweight local and CI scanning, and a broad community and commercial rule ecosystem.
- Sourcegraph code search: Cross-repository code search and navigation for discovering patterns, ownership context, and repeated implementation drift at scale. Moat: Organization-scale indexing and precise code navigation across many repositories and revisions.
- ast-grep: Structural code search and rewriting based on abstract syntax-tree patterns rather than plain text matching. Moat: Concise structural patterns, language-aware matching, and efficient command-line automation.

## Honest gaps (grounded in repo facts)
- The facts describe repository-file drift, policy-history signals, consistency scores, and a research comparison, but do not establish per-check scoring rubrics, severity definitions, or false-positive/false-negative disclosures comparable to OpenSSF Scorecard.
- The declared scan samples only 4, 6, or 8 public repositories, so its scores cannot establish organization-wide posture; the README already states this boundary.
- No facts establish semantic vulnerability analysis, data-flow queries, or a maintained security-rule corpus comparable to CodeQL.
- No facts establish user-authored static-analysis rules or CI rule enforcement comparable to Semgrep; the service also explicitly performs no policy change or write action.
- No facts establish AST-structural pattern search or rewriting comparable to ast-grep.
- No facts establish organization-scale indexed code search, symbol navigation, or historical revision search comparable to Sourcegraph.
- The browser scanner and optional Python service are distinct evidence paths, but the facts do not provide a cross-path conformance report proving identical findings and scores for the same sampled inputs.
- Successful observations are cached for ten minutes with their original observedAt, but the facts do not specify cache provenance in exports, scanner-version identity, or source commit pinning for reproducibility.
- The README says a browser-exported digest is not a signed Khipu receipt; therefore the facts do not support claiming signed provenance, deployment attestation, or independent verification.
- The repository metadata has pushed_at null, and the README explicitly separates source candidacy from tests, builds, commits, Space builds, publishing, product routes, and proof routes; no current runtime or deployment receipt is established.
- The supplied readme_head is truncated at ATLAS_ALLO, so complete cross-origin configuration and any later documentation claims cannot be audited from these facts.
- The facts establish TypeScript as primary language and a Python/FastAPI backend, but provide no test counts, coverage, benchmark results, accuracy measurements, or completed local/CI verification readback.

## Dosed upgrade plan
- Dose 1, propose only: define a versioned AuditResult v1 check taxonomy with measured, blocked, not_applicable, and not_checked states; map every existing drift, policy-history, and consistency output to evidence requirements and explicit limitations.
- Dose 2, propose only: add a sample manifest containing requested and completed sample size, repository identifiers, observedAt values, scanner path, failures, and available source revision/file metadata; retain incomplete evidence rather than converting it into a score.
- Dose 3, propose only: publish per-check rationale and uncertainty notes in the UI and export, including sampled-scope language and a clear distinction between not_checked and passing.
- Dose 4, propose only: create browser-versus-Python contract fixtures for success, partial evidence, 429, 503, cache reuse, and configured-API failure; verify that prior evidence is retained and never relabeled as a fresh fallback scan.
- Dose 5, propose only: add reproducibility metadata for check definitions and scanner versions, and show cache age and original observedAt wherever cached evidence is displayed or exported.
- Dose 6, propose only: evaluate read-only Semgrep or ast-grep checks as an optional local experiment on the same bounded public sample; report their outputs separately and do not add repository writes, enforcement, arbitrary organizations, or browser tokens.
- Dose 7, propose only: assess CodeQL separately for supported languages and semantic vulnerability use cases, with explicit not_checked results when unavailable; do not represent it as part of the existing audit until independently verified.
- Dose 8, propose only: benchmark any expanded cross-repository search against the current bounded collector for latency, rate-limit behavior, completeness, and result agreement before considering a contract revision.
- Dose 9, propose only: run the documented Node and Python verification commands and record separate readbacks for lint, tests, type checking, build, backend tests, and any deployment or proof route; source changes alone remain non-deployment evidence.
- Risk note: Medium: the existing evidence boundary is unusually explicit, but adding leader-like scoring or analysis could overstate a small public sample, create browser/Python divergence, increase GitHub rate-limit exposure, or imply security assurance that the current read-only file audit does not provide. The largest immediate risks are reproducibility and presentation of unchecked or incomplete evidence; semantic-analysis expansion should remain isolated and optional until measured.
- Propose-only note: This is a proposal, not an implementation or authorization. No repository edit, policy enforcement, deployment, signed receipt, organization-wide certification, or unverified tool integration is claimed. Each dose requires its own diff review, tests, and runtime readback before promotion.

## Advisory notes (unverified rails, non-binding)
- astra: YARQA-ATTN: Hardware-specific compiler optimizations for proprietary AI accelerators. curation-atlas: Real-time integration with private enterprise security telemetry. david-leads: Proprietary cross-referenced datasets of non-public government procurement.
- sol: YARQA-ATTN: Hardware-specific Triton/CUDA optimization primitives curation-atlas: Real-time GitHub event stream ingestion pipeline david-leads: Proprietary DSSE-evidence signal mapping schema
- claude: YARQA-ATTN: Hardware-specific compiler optimizations for proprietary AI accelerators. curation-atlas: Direct API integration with private enterprise security telemetry streams. david-leads: Exclusive access to non-public government procurement and intelligence feeds.

## DO NOT MERGE
This plan is a proposal artifact of the 10-pass OUROBOROS loop (loop-5 of 10). No code, no CI, no behavior changes in this file. A reviewer with authority may convert to a work order later.