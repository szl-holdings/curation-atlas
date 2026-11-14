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
