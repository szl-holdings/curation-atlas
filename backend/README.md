---
title: Curation Atlas API
emoji: 🧭
colorFrom: indigo
colorTo: blue
sdk: docker
app_port: 7860
---

# Curation Atlas API

Read-only, public-GitHub audit service for the fixed `szl-holdings` organization.
It does not apply policy, certify a repository, or attest a GitHub or HF deployment.
The response is an observation made over a non-atomic scan window.

* `GET /healthz`: process liveness and declared source revision. Liveness is not
  upstream readiness or source attestation.
* `GET /v1/orgs/szl-holdings/audit?sample_size=4`: bounded public inventory and
  deep sample, using the front end's `AuditResult` schema version 1.

Accepted sample sizes are 4, 6, and 8. Other organizations are not supported.
One uncached scan may run at a time; successful results are cached for ten minutes
without changing their original `observedAt`. HTTP 429/503 responses are not audit
results. Partial deep evidence is retained with `mode: "BLOCKED"`.

Set `ATLAS_ALLOWED_ORIGINS` to a comma-separated list of exact HTTPS Site origins
before browser integration. No wildcard CORS origin is accepted. Optionally set a
least-privilege `ATLAS_GITHUB_TOKEN` as a Space secret for GitHub rate capacity;
never place it in frontend source or a browser environment variable.
`ATLAS_SOURCE_REVISION` may be set to a full 40-character source commit only after
the deployed bytes are bound to that revision by the publisher. Otherwise the
health response reports the binding as `UNKNOWN`.

Local verification:

```text
python -m unittest discover -s tests -v
uvicorn app:app --host 127.0.0.1 --port 7860
```

The Space's runtime should be probed independently after its exact source revision
and build status are read back. A running Space or HTTP 200 alone is not a release
qualification.
