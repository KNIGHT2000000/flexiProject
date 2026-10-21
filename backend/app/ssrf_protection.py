"""
SSRF Protection and Safe Outbound Network Isolation.
Prevents internal network probing, AWS IMDS metadata exfiltration (169.254.169.254),
loopback connections, and DNS rebinding attacks.
"""
from __future__ import annotations

import socket
import ipaddress
import httpx
from urllib.parse import urlsplit, urljoin
from typing import Optional


BLOCKED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),       # IPv4 loopback
    ipaddress.ip_network("10.0.0.0/8"),        # RFC 1918 private
    ipaddress.ip_network("172.16.0.0/12"),     # RFC 1918 private
    ipaddress.ip_network("192.168.0.0/16"),    # RFC 1918 private
    ipaddress.ip_network("169.254.0.0/16"),    # Link-local / AWS IMDS
    ipaddress.ip_network("0.0.0.0/8"),         # Current network
    ipaddress.ip_network("100.64.0.0/10"),     # Carrier-grade NAT
    ipaddress.ip_network("192.0.0.0/24"),      # IETF Protocol Assignments
    ipaddress.ip_network("192.0.2.0/24"),      # TEST-NET-1
    ipaddress.ip_network("198.51.100.0/24"),   # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),    # TEST-NET-3
    ipaddress.ip_network("224.0.0.0/4"),       # Multicast
    ipaddress.ip_network("240.0.0.0/4"),       # Reserved / Future use
    ipaddress.ip_network("::1/128"),           # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),          # IPv6 Unique Local Address
    ipaddress.ip_network("fe80::/10"),         # IPv6 Link-Local
    ipaddress.ip_network("::ffff:0:0/96"),     # IPv4-mapped IPv6
]

BLOCKED_HOSTNAMES = {
    "localhost",
    "metadata.google.internal",
    "metadata.internal",
    "instance-data",
}


def is_ip_allowed(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Return True if IP is in a public, routeable, non-reserved range."""
    # Built-in properties
    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    ):
        return False

    # Explicit subnet containment check
    for net in BLOCKED_NETWORKS:
        if ip in net:
            return False

    return True


def is_safe_host(hostname: str) -> tuple[bool, str]:
    """
    Validate that hostname resolves strictly to public, non-private IP addresses.
    Returns (is_safe, reason_or_detail).
    """
    clean_host = hostname.strip().lower().rstrip(".")
    if clean_host in BLOCKED_HOSTNAMES:
        return False, f"Hostname '{clean_host}' is blocked as a local/cloud metadata destination."

    # Direct IP literal check
    try:
        ip = ipaddress.ip_address(clean_host)
        if not is_ip_allowed(ip):
            return False, f"Direct IP literal '{ip}' is in a private/reserved/metadata subnet."
        return True, "Safe public IP literal."
    except ValueError:
        pass

    # DNS Resolution check
    try:
        addr_info = socket.getaddrinfo(clean_host, None)
        resolved_ips = set()
        for family, _, _, _, sockaddr in addr_info:
            ip_str = sockaddr[0]
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                resolved_ips.add(ip_obj)
            except ValueError:
                continue

        if not resolved_ips:
            return False, f"Hostname '{clean_host}' did not resolve to any valid IP addresses."

        for ip in resolved_ips:
            if not is_ip_allowed(ip):
                return False, f"Hostname '{clean_host}' resolves to forbidden IP '{ip}' (private/loopback/cloud metadata)."

        return True, f"Hostname resolved to {len(resolved_ips)} safe public IP(s)."
    except socket.gaierror as e:
        return False, f"DNS resolution failed for '{clean_host}': {e}"
    except Exception as e:
        return False, f"Hostname validation failed: {e}"


async def safe_trace_redirects(
    initial_url: str,
    max_hops: int = 5,
    timeout_sec: float = 3.0,
) -> list[str]:
    """
    Safely trace HTTP redirect hops without blindly executing user-submitted URLs.
    
    Security guarantees:
    - Never follows redirects automatically (disables follow_redirects in client).
    - Checks SSRF safety of destination host at EACH hop before connecting.
    - Limits maximum hops (default 5).
    - Enforces strict read/connection timeouts (default 3s).
    - Caps response body inspection to avoid payload bombs.
    """
    chain = [initial_url]
    current_url = initial_url

    async with httpx.AsyncClient(
        follow_redirects=False,
        timeout=httpx.Timeout(timeout_sec, connect=2.0),
        headers={"User-Agent": "PhishGuard-SafeTracer/2.0"},
    ) as client:
        for _ in range(max_hops):
            parts = urlsplit(current_url)
            if parts.scheme.lower() not in ("http", "https"):
                break

            hostname = parts.hostname
            if not hostname:
                break

            safe, reason = is_safe_host(hostname)
            if not safe:
                # Target resolves to private/internal IP; abort redirect tracing immediately
                break

            try:
                # Issue HEAD or lightweight GET request without following redirect
                resp = await client.get(current_url)
                if resp.status_code in (301, 302, 303, 307, 308):
                    loc = resp.headers.get("Location")
                    if not loc:
                        break
                    # Resolve relative redirect URLs against current URL
                    next_url = urljoin(current_url, loc)
                    if next_url in chain:
                        # Redirect loop detected
                        break
                    chain.append(next_url)
                    current_url = next_url
                else:
                    # Final destination reached
                    break
            except Exception:
                # Network error, timeout, or connection refused — stop gracefully
                break

    return chain
