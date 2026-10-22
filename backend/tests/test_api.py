"""
Basic API integration tests using FastAPI TestClient.
Run with: pytest tests/
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_health_check():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_root():
    r = client.get("/")
    assert r.status_code == 200


def test_register_and_login():
    # Register
    r = client.post("/api/auth/register", json={
        "username": "pytest_user",
        "email": "pytest@test.com",
        "password": "testpass123",
    })
    # 200 = created, 400 = already exists (re-run)
    assert r.status_code in (200, 400)

    # Login
    r = client.post("/api/auth/login", data={
        "username": "pytest_user",
        "password": "testpass123",
    })
    assert r.status_code == 200
    assert "access_token" in r.json()


def test_scan_url_unauthenticated():
    """Unauthenticated scan should still work (guest mode)."""
    r = client.post("/api/scan/url", json={"url": "https://google.com"})
    assert r.status_code == 200
    data = r.json()
    assert "prediction" in data
    assert "risk_score" in data
    assert data["prediction"] in ("legitimate", "suspicious", "phishing")


def test_threat_feed_public():
    """Threat feed is public — no auth needed."""
    r = client.get("/api/scan/feed")
    assert r.status_code == 200
    assert isinstance(r.json(), list)


def test_scan_malqr_exploit_endpoint():
    """Verify MalQR QR exploit payloads are flagged as critical phishing/exploits without HTTP 400 error."""
    r = client.post("/api/scan/url", json={"url": "'or'x'='x"})
    assert r.status_code == 200
    data = r.json()
    assert data["prediction"] == "phishing"
    assert data["risk_score"] == 100.0
    assert data["features"].get("is_exploit_payload") == 1
    assert "CRITICAL MALICIOUS EXPLOIT" in data["recommendations"][0]


def test_demo_admin_auto_seeding():
    """Verify default demo and admin credentials exist and can authenticate."""
    r = client.post("/api/auth/login", data={"username": "demo", "password": "Demo@12345"})
    assert r.status_code == 200
    assert "access_token" in r.json()

    r_admin = client.post("/api/auth/login", data={"username": "admin", "password": "Admin@12345"})
    assert r_admin.status_code == 200
    assert "access_token" in r_admin.json()

