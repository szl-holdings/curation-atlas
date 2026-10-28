export type MethodKey = "curateevo" | "scaffolded" | "gocam";

export const methods: Array<{
  key: MethodKey;
  name: string;
  kicker: string;
  definition: string;
  evidence: string;
  limitation: string;
}> = [
  {
    key: "curateevo",
    name: "CurateEvo",
    kicker: "Failure-driven curation-code evolution",
    definition:
      "Represents a curation strategy as executable code, uses failed held-out development trajectories to revise that code, then emits SFT data, RL data, and an inference-time memory bank.",
    evidence:
      "REPORTED (v1): 0.51M tokens and 405 seconds of curation overhead per 1,000 retained training turns, averaged over three benchmarks—about 48% fewer tokens and 50% less wall time than the mean prior baseline.",
    limitation:
      "The current artifact is an arXiv v1 preprint. No official implementation is linked from arXiv or the Hugging Face paper record, and none was located in a bounded official-source search; no independent replay was located. The overhead excludes repeated post-training and evaluation.",
  },
  {
    key: "scaffolded",
    name: "Scaffolded agents",
    kicker: "Method-grounded policy search",
    definition:
      "Curation-Bench fixes the data pool, model, training recipe, evaluation, budget, and contamination rules while a general coding agent edits an executable selection or rewriting policy.",
    evidence:
      "REPORTED (v2): the best observed Adapt-Papers 10K trajectory scored 34.9, with a condition mean of 34.0±0.8, above the evaluated ARDS-100K baseline at 34.1; new-policy-family moves rose from 27% to 67%.",
    limitation:
      "DECLARED replay surface (official repository at 24eea15): the runnable uv/Docker harness exposes eight fixed tasks, contamination auditing, and plain, instruction, and skill-grounded protocols with paper-derived skill cards. REPORTED results were not independently replayed here; the documented setup requires GPU hardware, model and data downloads, and at least 1 TB of free disk. Self-Research underperformed open prompting, so more structure is not monotonically better.",
  },
  {
    key: "gocam",
    name: "GO-CAM builders",
    kicker: "Evidence-centered causal modeling",
    definition:
      "GO-CAM combines standard Gene Ontology annotations into causal activity networks. Noctua is the production curation platform; the workshop used a curator-controlled sidecar against a non-production server, while a separate experimental prototype turns figures or gene lists into draft gocam-py models.",
    evidence:
      "REPORTED workflow feasibility plus traceability: 35 of 37 workshop participants used the sidecar and nine created models; GO-CAM uses evidence codes and references, while the prototype emits assertion-level sources and labels unsupported inference as instinct.",
    limitation:
      "Neither the workshop nor the prototype reports a controlled GO-CAM biological-accuracy, curator-time, or production-throughput benchmark. Expert review remains required.",
  },
];

export const comparisonRows: Array<{
  dimension: string;
  curateEvo: string;
  scaffolded: string;
  gocam: string;
}> = [
  {
    dimension: "Artifact optimized",
    curateEvo: "Curation code producing SFT, RL, and memory resources",
    scaffolded: "Executable selection or rewriting policy under a fixed budget",
    gocam: "Ontology-conformant causal activity model with evidence metadata",
  },
  {
    dimension: "Adaptation loop",
    curateEvo: "Failures drive code rewrites, pruning, and rollback",
    scaffolded: "Agent proposes, implements, trains, evaluates, and revises",
    gocam: "Evidence retrieval, ontology mapping, validation, and expert review",
  },
  {
    dimension: "Human labor",
    curateEvo: "Automates repeated diagnosis once corpora and evaluators exist; no labor-hours study",
    scaffolded: "Automates the benchmark loop; humans still define tasks, scaffolds, and review",
    gocam: "Deliberately assists domain experts rather than replacing them",
  },
  {
    dimension: "Provenance",
    curateEvo: "Executable curation code and held-out development/test separation; not claim-level provenance",
    scaffolded: "Commits, manifests, scores, and contamination audits; explicit method citations under Adapt Papers",
    gocam: "Standard evidence codes and references; prototype assertion-level source objects",
  },
  {
    dimension: "Validation burden",
    curateEvo: "High: re-curate, retrain, and evaluate every epoch",
    scaffolded: "High: schema, budget, contamination, fine-tune, and multi-benchmark evaluation",
    gocam: "Domain-specific assurance burden: ontology, references, schema validation, and expert review",
  },
  {
    dimension: "Best fit",
    curateEvo: "Repeated post-training from noisy agent trajectories",
    scaffolded: "Automated research over data-selection and rewriting policies",
    gocam: "Expert-reviewed scientific curation where evidence constrains autonomy",
  },
];

export const sources = [
  { label: "CurateEvo paper", url: "https://arxiv.org/abs/2607.06140v1", kind: "paper" },
  { label: "CurateEvo full text", url: "https://arxiv.org/html/2607.06140v1", kind: "paper" },
  { label: "Curation-Bench paper", url: "https://arxiv.org/abs/2606.04261v2", kind: "paper" },
  { label: "Curation-Bench project", url: "https://feiyang-k.github.io/curation-bench/", kind: "official" },
  { label: "Curation-Bench runnable repository (observed commit)", url: "https://github.com/feiyang-k/curation-bench/tree/24eea1526492c00cee421f5db0793789e00aabb2", kind: "code" },
  { label: "Beaver scientific-curation harness", url: "https://arxiv.org/abs/2606.21005v2", kind: "paper" },
  { label: "GO agent workshop paper", url: "https://arxiv.org/abs/2608.27675v1", kind: "paper" },
  { label: "GO-CAM overview", url: "https://geneontology.org/docs/gocam-overview/", kind: "official" },
  { label: "GO-CAM foundational paper", url: "https://www.nature.com/articles/s41588-019-0500-1", kind: "paper" },
  { label: "Noctua", url: "https://github.com/geneontology/noctua", kind: "code" },
  { label: "gocam-py", url: "https://github.com/geneontology/gocam-py", kind: "code" },
  { label: "noctua-py sidecar", url: "https://github.com/geneontology/noctua-py", kind: "code" },
  { label: "GO workshop infrastructure", url: "https://github.com/geneontology/go-jupyter", kind: "code" },
  { label: "Pathways2GO", url: "https://github.com/geneontology/pathways2GO", kind: "code" },
  { label: "Experimental figure-to-GO-CAM prototype", url: "https://github.com/geneontology/go-prototype-0000001", kind: "code" },
  { label: "Prototype live publication", url: "https://geneontology.github.io/go-prototype-0000001/", kind: "official" },
];

export const frontierHypothesis = {
  title: "A provenance-bearing evolutionary curator",
  body:
    "Evolve curation code from failure feedback as CurateEvo does; require every non-baseline mutation to cite, instantiate, adapt, implement, and validate a prior method as Curation-Bench does; then add assertion-level provenance-completeness scoring and deterministic validation gates inspired by GO-CAM semantics and the prototype.",
  caveat:
    "This is an architectural hypothesis, not a reported result. No cited study tests the combination end to end.",
};
