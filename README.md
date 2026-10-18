# Curation Atlas

Curation Atlas is a public-source curation audit for the `szl-holdings` GitHub
organization. The React/Vinext frontend presents repository-file drift,
policy-history signals, consistency scores, and a research comparison. The
optional Python/FastAPI service performs a bounded public GitHub scan and
returns the frontend's `AuditResult` v1 contract. Neither component edits
repositories or enforces policy.

This repository is a **source candidate**, not a deployment receipt. A local
test, build, GitHub commit, Hugging Face Space build, Site publish, product
route, and proof route are separate states that each require their own readback.

## Shape and evidence boundary

- `app/` and `lib/` contain the browser UI, public GitHub scanner, comparison,
  and optional Python API adapter. Without `NEXT_PUBLIC_ATLAS_API_BASE`, a new
  audit uses the browser scanner. With a configured API origin, an audit of
  `szl-holdings` uses the Python service. If that request fails, the UI retains
  the preceding evidence; it does not silently relabel a fallback scan.
- `backend/audit.py` is a read-only, public-repository collector. `backend/app.py`
  serves `GET /healthz` and `GET /v1/orgs/szl-holdings/audit?sample_size=4`.
  Sample sizes are limited to 4, 6, or 8. Successful observations are cached
  for ten minutes with their original `observedAt`; 429 and 503 are failures,
  not audit results. See [backend/README.md](backend/README.md) for the API
  contract and deployment settings.
- `MEASURED` describes a fresh source observation that completed the declared
  scan. `BLOCKED` retains incomplete evidence. Scores describe only the
  sampled public repositories; they are not an organization-wide certification.
  A browser-exported digest is not a signed Khipu receipt. Source, runtime,
  evaluation, and authorization remain distinct.
- The service accepts no arbitrary organization, private-repository token from
  a browser, write action, model decode, or policy change. A server-side
  `ATLAS_GITHUB_TOKEN` is optional for rate capacity and must be stored only as
  a deployment secret.

## Local verification

The frontend requires Node.js 22.13 or newer. From this directory:

```text
npm ci
npm test
npx tsc --noEmit
npm run build
npm run dev
```

The backend requires Python 3.12. From `backend/`:

```text
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python -m uvicorn app:app --host 127.0.0.1 --port 7860
```

For a cross-origin local frontend preview, set
`ATLAS_ALLOWED_ORIGINS=http://localhost:5173` in the backend environment and
`NEXT_PUBLIC_ATLAS_API_BASE=http://127.0.0.1:7860` in the frontend environment
before starting them. Use the actual preview origin if its port or hostname
differs. Loopback HTTP is development-only; a hosted API origin must be exact
HTTPS. `ATLAS_SOURCE_REVISION` may be set to a full source SHA only after the
publisher binds the deployed bytes to that revision. `/healthz` reports process
liveness, not upstream readiness or release attestation.

The CI workflow repeats the locked npm install, frontend tests/typecheck/build,
and direct-version-pinned Python dependency install/unit tests. Transitive Python
dependencies are not yet hash-locked. CI success does not prove a
Space or Site is running.

## Governed release chain

1. Create the dedicated `szl-holdings/curation-atlas` GitHub repository, push a
   reviewed exact source head, and read back its branch rules, checks, and
   resulting merge SHA. Do not bypass a required protected-merge path.
2. Publish the API to a separate `SZLHOLDINGS/curation-atlas` Docker Space from
   that source. Keep the Space on CPU Basic unless a separately authorized
   upgrade is needed; set an exact Site origin in `ATLAS_ALLOWED_ORIGINS` and
   keep any GitHub token in Space secrets. Read back the immutable Space commit,
   build result, and JSON API behavior. A `RUNNING` label or HTTP 200 alone is
   not qualification. Do not add another writer to A11oy's canonical Space.
3. Point the frontend at the verified API origin, test the integrated browser
   flow, and publish the exact frontend head to its identified Site project.
   Preserve that project's access policy; a similarly titled Site is not an
   interchangeable target.
4. Change `a-11-oy.com` product navigation and `a11oy.net` proof content through
   their respective canonical owners and normal review paths. The proof page
   should cite the actual source, deployment, and runtime receipts, marking
   missing witnesses `UNKNOWN` or `UNAVAILABLE`. Do not change DNS or the
   canonical A11oy HF publisher as a shortcut.

Until each step has an independent readback, its release state remains
`UNKNOWN` or `UNAVAILABLE`; this README is not a publication claim.
