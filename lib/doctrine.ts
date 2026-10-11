export const doctrineReadback = {
  observedAt: "2026-10-03T06:59:33Z",
  organizationHead: "cce50ac8b27f6db50d882423d3fd9bb784e0a4cd",
  findings: [
    {
      status: "BLOCKED",
      title: "Organization provenance wording conflicts",
      summary:
        "Doctrine v11 says L1 honest and L2 attested-but-not-independently-verified; TRUST says L2–L3 are roadmap; PROVENANCE_NOTICE says organization L2 is not attested. The organization-wide posture cannot be silently averaged into a pass.",
      links: [
        { label: "Doctrine v11", url: "https://github.com/szl-holdings/.github/blob/cce50ac8b27f6db50d882423d3fd9bb784e0a4cd/doctrine/DOCTRINE_V11.md#L63-L72" },
        { label: "TRUST", url: "https://github.com/szl-holdings/.github/blob/cce50ac8b27f6db50d882423d3fd9bb784e0a4cd/TRUST.md#L15-L23" },
        { label: "Provenance notice", url: "https://github.com/szl-holdings/.github/blob/cce50ac8b27f6db50d882423d3fd9bb784e0a4cd/PROVENANCE_NOTICE.md#L1-L23" },
      ],
    },
    {
      status: "MEASURED",
      title: "Policy instructions disagree with the immutable tree",
      summary:
        "At the pinned .github head, AGENTS.md says actionlint covers 15 workflows and that no Makefile exists. The same immutable tree contains 134 workflow YAML files and a Makefile; 22 workflows match the reusable naming convention.",
      links: [
        { label: "AGENTS.md", url: "https://github.com/szl-holdings/.github/blob/cce50ac8b27f6db50d882423d3fd9bb784e0a4cd/AGENTS.md#L20-L24" },
        { label: "Makefile", url: "https://github.com/szl-holdings/.github/blob/cce50ac8b27f6db50d882423d3fd9bb784e0a4cd/Makefile" },
      ],
    },
    {
      status: "BLOCKED",
      title: "Lean counts are not comparable without scope and SHA",
      summary:
        "The locked 749/14/163 baseline, README whole-tree text counts, PROVEN_FORMULAS counts, and SORRIES corpus count use different methods and revisions. PROVEN_FORMULAS still labels an older count current main; the dashboard keeps every scope separate.",
      links: [
        { label: "Current README", url: "https://github.com/szl-holdings/lutar-lean/blob/3b0b589ea332fe962afff13328d9675b525e1819/README.md#L57" },
        { label: "Proven formulas", url: "https://github.com/szl-holdings/lutar-lean/blob/3b0b589ea332fe962afff13328d9675b525e1819/PROVEN_FORMULAS.md#L13-L15" },
        { label: "SORRIES scope", url: "https://github.com/szl-holdings/lutar-lean/blob/3b0b589ea332fe962afff13328d9675b525e1819/SORRIES.md#L3-L6" },
      ],
    },
  ],
} as const;
