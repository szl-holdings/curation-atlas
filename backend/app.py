"""FastAPI transport for the bounded Curation Atlas public audit."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import time
from contextlib import asynccontextmanager
from typing import Any
from urllib.parse import urlsplit

import httpx
from fastapi import FastAPI, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse

from audit import AuditError, GitHubReader, ORG, scan_organization

SHA_RE = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)
CACHE_SECONDS = 600
SCAN_TIMEOUT_SECONDS = 120
_cache: dict[int, tuple[float, dict[str, Any], str]] = {}
_scan_lock = asyncio.Lock()


def allowed_origins() -> list[str]:
    raw = os.getenv("ATLAS_ALLOWED_ORIGINS", "")
    origins = [value.strip().rstrip("/") for value in raw.split(",") if value.strip()]
    for origin in origins:
        parsed = urlsplit(origin)
        local = parsed.scheme == "http" and parsed.hostname in ("localhost", "127.0.0.1")
        if (not (parsed.scheme == "https" or local) or not parsed.netloc or
                parsed.path or parsed.query or parsed.fragment or parsed.username or
                parsed.password or "*" in origin):
            raise RuntimeError("ATLAS_ALLOWED_ORIGINS must contain exact HTTPS or loopback origins.")
    return sorted(set(origins))


def declared_revision() -> str | None:
    value = os.getenv("ATLAS_SOURCE_REVISION", "")
    return value if SHA_RE.fullmatch(value) else None


@asynccontextmanager
async def lifespan(application: FastAPI):
    limits = httpx.Limits(max_connections=4, max_keepalive_connections=2)
    timeout = httpx.Timeout(connect=5, read=15, write=5, pool=5)
    async with httpx.AsyncClient(limits=limits, timeout=timeout, follow_redirects=False) as client:
        application.state.github_client = client
        yield


API_DESCRIPTION = (
    "Bounded public GitHub observations; not a policy effector or release attestation."
)

app = FastAPI(
    title="Curation Atlas API",
    version="1.0.0",
    description=API_DESCRIPTION,
    lifespan=lifespan,
)
ALLOWED_ORIGINS = allowed_origins()
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET"],
    allow_headers=["Accept", "If-None-Match"],
)


def source_binding() -> dict[str, Any]:
    revision = declared_revision()
    return {
        "sourceRevision": revision,
        "sourceBinding": "DECLARED" if revision else "UNKNOWN",
        "upstreamReadiness": "UNKNOWN",
    }


def _browser_front_page(payload: dict[str, Any]) -> str:
    """Responsive, honest landing page mirroring the headless JSON payload."""
    entrypoints = "".join(
        "<li><code>GET " + str(e["path"]) + "</code> &mdash; " + str(e["purpose"]) + "</li>"
        for e in payload["entrypoints"]
    )
    revision = str(payload.get("sourceRevision") or "UNKNOWN")
    binding = str(payload.get("sourceBinding") or "UNKNOWN")
    readiness = str(payload.get("upstreamReadiness") or "UNKNOWN")
    return """<!doctype html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Curation Atlas</title>
<style>
:root{--bg:#0b0e14;--panel:#121722;--ink:#e8ecf4;--dim:#9aa7bd;--line:#232c3d;--accent:#5eead4}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;line-height:1.6}
.wrap{max-width:860px;margin:0 auto;padding:28px 20px 48px}
h1{font-size:clamp(1.5rem,5vw,2.2rem);margin:.3em 0}
p,li{color:var(--dim)}
a{color:var(--accent)}
code{background:#0e1420;border:1px solid var(--line);border-radius:6px;padding:2px 6px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:18px;margin-top:18px}
.badge{display:inline-block;padding:7px 12px;border:1px solid var(--line);border-radius:999px;margin:4px 6px 12px 0;text-decoration:none;color:var(--ink);background:#0e1420}
</style>
</head>
<body>
<div class="wrap">
<h1>Curation Atlas</h1>
<p>__DESC__</p>
<div>
<a class="badge" href="/healthz">status: /healthz</a>
<a class="badge" href="https://huggingface.co/SZLHOLDINGS">Hugging Face org</a>
<a class="badge" href="https://github.com/szl-holdings/curation-atlas">source repository</a>
</div>
<div class="card"><strong>Headless API</strong><p>Role: __ROLE__. Source revision: __REV__ (__BINDING__ binding; upstream readiness __READY__).</p><ul>__ENTRYPOINTS__</ul></div>
<div class="card"><strong>Receipts layer</strong><p>Exported receipts are self-asserted SHA-256 digests (UNSIGNED): anyone can make one that verifies, and they do not establish author or GitHub origin. Fail-closed: unmeasured things say NOT MEASURED.</p></div>
<footer style="margin-top:30px;color:var(--dim);font-size:.85rem">Browsers get this page; API clients (Accept: application/json) get the unchanged headless payload.</footer>
</div>
</body>
</html>"""         .replace("__DESC__", str(payload["description"]))         .replace("__ROLE__", str(payload["role"]))         .replace("__REV__", revision)         .replace("__BINDING__", binding)         .replace("__READY__", readiness)         .replace("__ENTRYPOINTS__", entrypoints)


@app.get("/")
async def service_index(request: Request):
    """Headless entry for API clients; a responsive page for browsers.

    Content negotiation on the Accept header: browsers send text/html and
    get an honest landing page; everything else gets the unchanged JSON
    headless payload. This does not attest readiness either way.
    """
    """Headless entry. Names the documented API; it does not attest readiness."""
    payload = {
        "service": "curation-atlas-api",
        "schemaVersion": 1,
        "role": "HEADLESS_API",
        "description": API_DESCRIPTION,
        **source_binding(),
        "entrypoints": [
            {
                "method": "GET",
                "path": "/healthz",
                "purpose": (
                    "process liveness and declared source revision; "
                    "not upstream readiness or release attestation"
                ),
            },
            {
                "method": "GET",
                "path": "/v1/orgs/szl-holdings/audit",
                "query": {"sample_size": [4, 6, 8]},
                "purpose": "bounded public audit observation",
            },
        ],
    }
    if "text/html" in request.headers.get("accept", ""):
        return HTMLResponse(
            content=_browser_front_page(payload),
            headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"},
        )
    return JSONResponse(
        content=payload,
        headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"},
    )


@app.get("/healthz")
async def healthz() -> dict[str, Any]:
    return {
        "status": "PROCESS_ALIVE",
        "evidence": "MEASURED",
        "service": "curation-atlas-api",
        "schemaVersion": 1,
        **source_binding(),
    }


@app.get("/readyz", include_in_schema=False)
async def readyz() -> JSONResponse:
    """Operational probe for a recent *sampled* audit, never release admission."""
    now = time.monotonic()
    measured = any(
        0 <= now - observed < CACHE_SECONDS
        and result.get("mode") == "MEASURED"
        for observed, result, _etag in _cache.values()
    )
    binding = source_binding()
    ready = measured and binding["sourceBinding"] == "DECLARED"
    return JSONResponse(
        status_code=200 if ready else 503,
        content={
            "ready": ready,
            "scope": "SAMPLED_PUBLIC_REPOSITORIES_ONLY",
            "sampleReadiness": "MEASURED" if measured else "UNKNOWN",
            **binding,
            "releaseReadiness": "NOT_ATTESTED",
        },
        headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"},
    )


def audit_response(result: dict[str, Any], etag: str, cached: bool) -> JSONResponse:
    headers = {
        "Cache-Control": "public, max-age=60",
        "Vary": "Origin",
        "ETag": etag,
        "X-Atlas-Observation": "cached" if cached else "fresh",
        "X-Content-Type-Options": "nosniff",
    }
    revision = declared_revision()
    if revision:
        headers["X-Atlas-Revision"] = revision
    return JSONResponse(content=result, headers=headers)


@app.get("/v1/orgs/{org}/audit")
async def audit(request: Request, org: str, sample_size: int = Query(default=4)) -> JSONResponse:
    origin = request.headers.get("origin")
    if origin is not None and origin not in ALLOWED_ORIGINS:
        return JSONResponse(
            status_code=403,
            content={"evidence": "BLOCKED", "code": "ORIGIN_NOT_ALLOWED",
                     "message": "This browser origin is not permitted."},
            headers={"Cache-Control": "no-store", "Vary": "Origin"},
        )
    if org != ORG:
        return JSONResponse(
            status_code=404,
            content={"evidence": "UNAVAILABLE", "code": "ORG_NOT_SUPPORTED",
                     "message": "Only the fixed public SZL organization is supported."},
        )
    if sample_size not in (4, 6, 8):
        return JSONResponse(
            status_code=422,
            content={"evidence": "UNAVAILABLE", "code": "INVALID_SAMPLE",
                     "message": "sample_size must be 4, 6, or 8."},
        )
    cached = _cache.get(sample_size)
    if cached and time.monotonic() - cached[0] < CACHE_SECONDS:
        return audit_response(cached[1], cached[2], True)
    if _scan_lock.locked():
        return JSONResponse(
            status_code=429,
            content={"evidence": "BLOCKED", "code": "SCAN_IN_PROGRESS",
                     "message": "A bounded audit is already running."},
            headers={"Retry-After": "5"},
        )
    async with _scan_lock:
        # A second caller may have populated the cache while waiting.
        cached = _cache.get(sample_size)
        if cached and time.monotonic() - cached[0] < CACHE_SECONDS:
            return audit_response(cached[1], cached[2], True)
        reader = GitHubReader(
            app.state.github_client, os.getenv("ATLAS_GITHUB_TOKEN") or None
        )
        try:
            result = await asyncio.wait_for(
                scan_organization(reader, sample_size), SCAN_TIMEOUT_SECONDS
            )
        except asyncio.TimeoutError:
            return JSONResponse(
                status_code=503,
                content={"evidence": "UNAVAILABLE", "code": "SCAN_TIMEOUT",
                         "message": "The bounded GitHub observation did not complete."},
                headers={"Retry-After": "30"},
            )
        except AuditError as exc:
            status = 429 if exc.status == 429 else 503
            headers = {"Retry-After": exc.retry_after or "60"} if status == 429 else {}
            return JSONResponse(
                status_code=status,
                content={"evidence": "UNAVAILABLE", "code": "GITHUB_SOURCE_UNAVAILABLE",
                         "message": str(exc), "rate": reader.rate},
                headers=headers,
            )
        canonical = json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        etag = '"' + hashlib.sha256(canonical.encode("utf-8")).hexdigest() + '"'
        _cache[sample_size] = (time.monotonic(), result, etag)
        return audit_response(result, etag, False)
