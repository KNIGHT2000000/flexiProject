"""
Unit tests for SSRF protection and safe redirect tracing.
"""
import pytest
import ipaddress
from app.ssrf_protection import is_ip_allowed, is_safe_host, safe_trace_redirects


def test_blocked_private_subnets():
    blocked_ips = [
        "127.0.0.1",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.169.254",  # AWS IMDS
        "0.0.0.0",
        "::1",              # IPv6 loopback
        "fe80::1",          # IPv6 link-local
    ]
    for ip_str in blocked_ips:
        ip = ipaddress.ip_address(ip_str)
        assert not is_ip_allowed(ip), f"Expected {ip_str} to be blocked"


def test_allowed_public_ips():
    allowed_ips = [
        "8.8.8.8",
        "1.1.1.1",
        "93.184.216.34",
    ]
    for ip_str in allowed_ips:
        ip = ipaddress.ip_address(ip_str)
        assert is_ip_allowed(ip), f"Expected {ip_str} to be allowed"


def test_is_safe_host_metadata():
    safe, reason = is_safe_host("169.254.169.254")
    assert not safe
    assert "private/reserved/metadata" in reason

    safe_local, _ = is_safe_host("localhost")
    assert not safe_local


@pytest.mark.anyio
async def test_safe_trace_redirects_blocks_private():
    # Attempting to trace redirects to AWS IMDS or localhost should immediately halt
    hops = await safe_trace_redirects("http://169.254.169.254/latest/meta-data/")
    assert hops == ["http://169.254.169.254/latest/meta-data/"]
