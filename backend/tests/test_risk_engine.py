"""
Unit tests for transparent risk aggregation and evidence synthesis.
"""
import pytest
from app.risk_engine import aggregate_risk, evaluate_heuristics, EvidenceStatus
from app.feature_extractor import extract_features, features_to_vector
from app.routers.scan import get_model


def test_heuristic_benign_evaluation():
    features = extract_features("https://google.com")
    pred, score, evidence = evaluate_heuristics(features)
    assert pred == "legitimate"
    assert score < 30.0


def test_heuristic_phishing_evaluation():
    # URL with IP, no HTTPS, suspicious keywords, excessive dots
    features = extract_features("http://192.168.1.1/login.verify.update.bank.account.security")
    pred, score, evidence = evaluate_heuristics(features)
    assert pred in ("suspicious", "phishing")
    assert score >= 40.0
    assert any(e.status == EvidenceStatus.SUSPICIOUS_HEURISTIC for e in evidence)


def test_whitelist_short_circuit():
    features = extract_features("https://suspicious-looking-url.com")
    res = aggregate_risk(features=features, is_whitelisted=True)
    assert res.prediction == "legitimate"
    assert res.risk_score == 0.0


def test_banned_domain_override():
    features = extract_features("https://banned-site.com")
    res = aggregate_risk(features=features, banned_reason="Admin flagged domain")
    assert res.prediction == "phishing"
    assert res.risk_score == 100.0


def test_virustotal_threat_boost():
    features = extract_features("https://clean-structure.com")
    vt_data = {"available": True, "malicious": 8, "suspicious": 2}
    res = aggregate_risk(features=features, virustotal_data=vt_data)
    assert res.prediction == "phishing"
    assert res.risk_score >= 90.0


def test_provider_error_does_not_clear_threat():
    # A provider timeout or error must never clear or decrease a high risk score
    features = extract_features("http://192.168.1.1/login.verify.secure")
    vt_error = {"available": False, "error": "Connection timed out"}
    whois_error = {"error": "WHOIS connection refused"}
    res = aggregate_risk(
        features=features,
        virustotal_data=vt_error,
        whois_data=whois_error,
    )
    assert any(e.status == EvidenceStatus.PROVIDER_ERROR for e in res.evidence)
    # The score must remain elevated from heuristics, never forced to 0.0
    assert res.risk_score >= 30.0


def test_ml_model_integration():
    model = get_model()
    assert model is not None, "Trained model.pkl should be successfully loaded"
    features = extract_features("https://www.google.com")
    vector = features_to_vector(features)
    res = aggregate_risk(features=features, ml_model=model, vector=vector)
    assert res.ml_prediction is not None
    assert res.ml_risk_score is not None
    assert res.prediction == "legitimate"


def test_dga_and_invalid_tld_detection():
    """Verify that keyboard-mash DGA strings with fake TLDs are classified as phishing."""
    from app.url_utils import validate_and_normalize_url

    url = "kskfnsfksnfksnf.com.randwa"
    val = validate_and_normalize_url(url)
    features = extract_features(val.normalized_url)
    model = get_model()
    vector = features_to_vector(features)
    res = aggregate_risk(features=features, ml_model=model, vector=vector, validation_result=val)

    assert res.prediction == "phishing"
    assert res.risk_score >= 80.0
    assert any("threat_intel.dga_entropy" in e.source or "threat_intel.invalid_tld" in e.source for e in res.evidence)


def test_brand_camouflage_shield():
    """Verify that unauthorized domains embedding trusted brand keywords are classified as phishing."""
    from app.url_utils import validate_and_normalize_url

    url = "https://paypal-security-update.com/login"
    val = validate_and_normalize_url(url)
    features = extract_features(val.normalized_url)
    model = get_model()
    vector = features_to_vector(features)
    res = aggregate_risk(features=features, ml_model=model, vector=vector, validation_result=val)

    assert res.prediction in ("phishing", "suspicious")
    assert res.risk_score >= 60.0
    assert any("brand_camouflage" in e.source for e in res.evidence)


def test_email_inspector_social_engineering():
    """Verify that urgency coercion, sender spoofing, and mismatched links are flagged."""
    from app.email_inspector import inspect_email

    sample = (
        'From: "PayPal Security" <support@paypa1-update.com>\n'
        'Subject: URGENT: Your account has been suspended within 24 hours\n\n'
        'Unauthorized login detected. Please click here to restore access:\n'
        '<a href="http://evil-trap.xyz/login">https://www.paypal.com</a>\n'
    )
    result = inspect_email(sample, [{"url": "http://evil-trap.xyz/login", "prediction": "phishing", "risk_score": 95.0}])
    assert result.email_prediction == "phishing"
    assert result.email_risk_score >= 80.0
    assert len(result.lures_detected) >= 2
    assert result.sender.is_spoofed is True
    assert len(result.mismatched_links) >= 1

