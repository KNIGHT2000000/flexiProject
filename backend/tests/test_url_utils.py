"""
Unit and regression tests for URL validation, normalization, and sanitization.
"""
import pytest
from app.url_utils import validate_and_normalize_url, redact_sensitive_url, detect_homoglyphs


def test_standard_https_normalization():
    res = validate_and_normalize_url("https://example.com")
    assert res.is_valid
    assert res.normalized_url == "https://example.com/"
    assert res.scheme == "https"
    assert res.hostname == "example.com"
    assert res.port is None
    assert not res.is_unusual_port


def test_scheme_defaulting():
    res = validate_and_normalize_url("google.com/search?q=test")
    assert res.is_valid
    assert res.normalized_url.startswith("https://google.com/search")
    assert res.scheme == "https"


def test_forbidden_schemes():
    for bad in ["javascript:alert(1)", "data:text/html,<script>", "file:///etc/passwd"]:
        res = validate_and_normalize_url(bad)
        assert not res.is_valid
        assert "Forbidden URL scheme" in res.error_message


def test_port_normalization():
    # Standard ports stripped
    assert validate_and_normalize_url("http://example.com:80/").port is None
    assert validate_and_normalize_url("https://example.com:443/").port is None
    assert not validate_and_normalize_url("https://example.com:443/").is_unusual_port

    # Unusual ports preserved and flagged
    unusual = validate_and_normalize_url("https://example.com:8443/admin")
    assert unusual.is_valid
    assert unusual.port == 8443
    assert unusual.is_unusual_port
    assert ":8443" in unusual.normalized_url


def test_punycode_and_idna():
    # IDN German umlaut
    res = validate_and_normalize_url("https://münchen.de")
    assert res.is_valid
    assert "xn--" in res.ascii_hostname
    assert res.has_punycode


def test_homoglyph_detection():
    # Cyrillic small 'a' (\u0430) instead of Latin 'a'
    cyrillic_paypal = "https://p\u0430ypal.com"
    res = validate_and_normalize_url(cyrillic_paypal)
    assert res.is_valid
    assert res.has_homoglyphs


def test_ip_address_detection():
    # IPv4 dotted decimal
    res1 = validate_and_normalize_url("http://192.168.1.1/login")
    assert res1.is_valid
    assert res1.is_ip_address
    assert res1.is_private_or_reserved_ip

    # Public IPv4
    res2 = validate_and_normalize_url("http://93.184.216.34/")
    assert res2.is_valid
    assert res2.is_ip_address
    assert not res2.is_private_or_reserved_ip


def test_url_length_limit():
    huge_url = "https://example.com/" + ("a" * 2050)
    res = validate_and_normalize_url(huge_url)
    assert not res.is_valid
    assert "maximum allowed length" in res.error_message


def test_sensitive_query_redaction():
    clean = redact_sensitive_url("https://portal.com/reset?token=secret12345&user=john&apiKey=xyz987")
    assert "token=%5BREDACTED%5D" in clean or "token=[REDACTED]" in clean
    assert "apiKey=%5BREDACTED%5D" in clean or "apiKey=[REDACTED]" in clean
    assert "user=john" in clean
