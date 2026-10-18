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
from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

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


app = FastAPI(
    title="Curation Atlas API",
    version="1.0.0",
    description="Bounded public GitHub observations; not a policy effector or release attestation.",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins(),
    allow_credentials=False,
    allow_methods=["GET"],
    allow_headers=["Accept", "If-None-Match"],
)


@app.get("/healthz")
async def healthz() -> dict[str, Any]:
    revision = declared_revision()
    return {
        "status": "PROCESS_ALIVE",
        "evidence": "MEASURED",
        "service": "curation-atlas-api",
        "schemaVersion": 1,
        "sourceRevision": revision,
        "sourceBinding": "DECLARED" if revision else "UNKNOWN",
        "upstreamReadiness": "UNKNOWN",
    }


def audit_response(result: dict[str, Any], etag: str, cached: bool) -> JSONResponse:
    headers = {
        "Cache-Control": "public, max-age=60",
        "ETag": etag,
        "X-Atlas-Observation": "cached" if cached else "fresh",
        "X-Content-Type-Options": "nosniff",
    }
    revision = declared_revision()
    if revision:
        headers["X-Atlas-Revision"] = revision
    return JSONResponse(content=result, headers=headers)


@app.get("/v1/orgs/{org}/audit")
async def audit(org: str, sample_size: int = Query(default=4)) -> JSONResponse:
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
