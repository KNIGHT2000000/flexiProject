import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.routers.threat import _clean_domain

client = TestClient(app)


def test_clean_domain_helper():
    assert _clean_domain("https://www.google.com/search?q=test") == "google.com"
    assert _clean_domain("http://example.org/path/sub") == "example.org"
    assert _clean_domain("sub.phishing-site.xyz") == "sub.phishing-site.xyz"
    assert _clean_domain("WWW.TEST.COM/") == "test.com"


def test_system_status_endpoint():
    res = client.get("/api/threat/system-status")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"
    assert data["version"] == "2.1.0"
    assert "ml_engine" in data
    assert data["ml_engine"]["features_extracted"] == 28
    assert "threat_providers" in data
    assert "database" in data


def test_dns_inspect_validation():
    # Invalid domain with no dot
    res_bad = client.get("/api/threat/dns-inspect?domain=invalid")
    assert res_bad.status_code == 400

    # Valid domain format
    res = client.get("/api/threat/dns-inspect?domain=google.com")
    assert res.status_code == 200
    data = res.json()
    assert data["domain"] == "google.com"
    assert "security_score" in data
    assert 0 <= data["security_score"] <= 100
    assert data["risk_level"] in ["LOW", "MEDIUM", "HIGH"]
    assert "mail_servers" in data
    assert "findings" in data
