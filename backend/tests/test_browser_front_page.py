"""Browser front page at "/" via content negotiation (fail-closed JSON intact)."""
from __future__ import annotations

from fastapi.testclient import TestClient

from app import app

BROWSER_ACCEPT = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"


def test_browsers_get_responsive_html():
    client = TestClient(app)
    response = client.get("/", headers={"Accept": BROWSER_ACCEPT})
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert 'name="viewport"' in response.text
    assert "Curation Atlas" in response.text
    assert "nosniff" in response.headers.get("x-content-type-options", "")


def test_api_clients_get_unchanged_json():
    client = TestClient(app)
    response = client.get("/", headers={"Accept": "application/json"})
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    body = response.json()
    assert body["service"] == "curation-atlas-api"
    assert body["role"] == "HEADLESS_API"
    assert any(e["path"] == "/healthz" for e in body["entrypoints"])


def test_default_request_keeps_headless_contract():
    client = TestClient(app)
    response = client.get("/")
    assert response.headers["content-type"].startswith("application/json")


def _html_and_json():
    client = TestClient(app)
    html = client.get("/", headers={"Accept": BROWSER_ACCEPT}).text
    body = client.get("/", headers={"Accept": "application/json"}).json()
    return html, body


def test_html_binding_matches_json_when_revision_unset(monkeypatch):
    monkeypatch.delenv("ATLAS_SOURCE_REVISION", raising=False)
    html, body = _html_and_json()
    assert body["sourceBinding"] == "UNKNOWN"
    assert "UNKNOWN binding" in html
    assert "DECLARED binding" not in html


def test_html_binding_declared_when_revision_set(monkeypatch):
    revision = "abc123" + "0" * 34
    monkeypatch.setenv("ATLAS_SOURCE_REVISION", revision)
    html, body = _html_and_json()
    assert body["sourceBinding"] == "DECLARED"
    assert "DECLARED binding" in html
    assert revision in html


def test_html_never_claims_signed_receipt():
    html, _ = _html_and_json()
    assert "signed receipt" not in html.lower()
    assert "UNSIGNED" in html
