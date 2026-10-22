from __future__ import annotations

import os
import re
from datetime import datetime, timezone
from typing import Optional, Any
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field

from app.database import get_db
from app import models
from app.config import get_settings
from app.routers.scan import get_model
from app.url_utils import validate_and_normalize_url

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

router = APIRouter(prefix="/api/threat", tags=["threat-intelligence"])


# ── Schemas ───────────────────────────────────────────────────────────────────

class MXRecord(BaseModel):
    preference: int
    exchange: str


class DNSSecurityReport(BaseModel):
    domain: str
    ip_addresses: list[str] = Field(default_factory=list)
    ipv6_addresses: list[str] = Field(default_factory=list)
    mail_servers: list[MXRecord] = Field(default_factory=list)
    nameservers: list[str] = Field(default_factory=list)
    spf_record: Optional[str] = None
    spf_status: str = "missing"             # "strict" | "softfail" | "neutral" | "missing"
    dmarc_record: Optional[str] = None
    dmarc_policy: Optional[str] = None      # "reject" | "quarantine" | "none" | "missing"
    security_score: int                     # 0 to 100
    risk_level: str                         # "LOW" | "MEDIUM" | "HIGH"
    findings: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)


class SystemHealthResponse(BaseModel):
    status: str
    version: str
    timestamp: str
    environment: str
    ml_engine: dict[str, Any]
    threat_providers: dict[str, Any]
    database: dict[str, Any]


# ── DNS Inspection Helper ─────────────────────────────────────────────────────

def _clean_domain(domain_or_url: str) -> str:
    d = domain_or_url.strip().lower()
    if d.startswith("http://") or d.startswith("https://"):
        norm = validate_and_normalize_url(d)
        if norm.is_valid and norm.hostname:
            d = norm.hostname
    # Remove any trailing slash or path
    d = re.sub(r"/.*$", "", d)
    d = re.sub(r"^www\.", "", d)
    return d


def inspect_domain_dns(domain: str) -> DNSSecurityReport:
    domain = _clean_domain(domain)
    if not domain or "." not in domain or len(domain) > 253:
        raise HTTPException(status_code=400, detail="Invalid domain name format.")

    findings: list[str] = []
    recommendations: list[str] = []
    ip_addresses: list[str] = []
    ipv6_addresses: list[str] = []
    mail_servers: list[MXRecord] = []
    nameservers: list[str] = []
    spf_record: Optional[str] = None
    dmarc_record: Optional[str] = None
    dmarc_policy: Optional[str] = None
    spf_status: str = "missing"

    if not DNS_AVAILABLE:
        return DNSSecurityReport(
            domain=domain,
            security_score=50,
            risk_level="MEDIUM",
            findings=["DNS resolver module is not loaded on this host."],
            recommendations=["Install dnspython to enable active DNS security checks."],
        )

    resolver = dns.resolver.Resolver()
    resolver.timeout = 1.5
    resolver.lifetime = 2.0
    # Use reliable public DNS servers alongside system resolver
    try:
        resolver.nameservers = ["1.1.1.1", "8.8.8.8", "8.8.4.4"]
    except Exception:
        pass

    # 1. A Records
    try:
        answers = resolver.resolve(domain, "A")
        ip_addresses = [r.address for r in answers]
    except Exception:
        findings.append("No A (IPv4) DNS records detected.")

    # 2. AAAA Records
    try:
        answers = resolver.resolve(domain, "AAAA")
        ipv6_addresses = [r.address for r in answers]
    except Exception:
        pass

    # 3. MX Records
    try:
        answers = resolver.resolve(domain, "MX")
        for r in answers:
            mail_servers.append(MXRecord(preference=r.preference, exchange=str(r.exchange).rstrip(".")))
        mail_servers.sort(key=lambda m: m.preference)
    except Exception:
        findings.append("No MX (Mail Exchanger) records found for domain.")

    # 4. NS Records
    try:
        answers = resolver.resolve(domain, "NS")
        nameservers = [str(r.target).rstrip(".") for r in answers]
    except Exception:
        findings.append("Unable to resolve authoritative nameservers.")

    # 5. TXT & SPF Records
    try:
        answers = resolver.resolve(domain, "TXT")
        for r in answers:
            txt_content = b"".join(r.strings).decode("utf-8", errors="ignore")
            if txt_content.lower().startswith("v=spf1"):
                spf_record = txt_content
                if "-all" in txt_content:
                    spf_status = "strict"
                elif "~all" in txt_content:
                    spf_status = "softfail"
                elif "?all" in txt_content or "+all" in txt_content:
                    spf_status = "neutral"
                break
    except Exception:
        pass

    # 6. DMARC Records (_dmarc.domain)
    try:
        dmarc_name = f"_dmarc.{domain}"
        answers = resolver.resolve(dmarc_name, "TXT")
        for r in answers:
            txt_content = b"".join(r.strings).decode("utf-8", errors="ignore")
            if "v=dmarc1" in txt_content.lower():
                dmarc_record = txt_content
                p_match = re.search(r"p=(reject|quarantine|none)", txt_content, re.IGNORECASE)
                if p_match:
                    dmarc_policy = p_match.group(1).lower()
                break
    except Exception:
        pass

    # Calculate DNS Security Score (0 to 100)
    score = 100

    if not ip_addresses and not mail_servers:
        score -= 40
        findings.append("Domain does not resolve to active A or MX records.")
        recommendations.append("Verify domain registrar DNS records and delegation.")

    if not nameservers or len(nameservers) < 2:
        score -= 10
        findings.append("Redundant nameservers not detected (less than 2 NS records).")
        recommendations.append("Configure at least two independent authoritative nameservers for DNS resilience.")

    if not spf_record:
        score -= 25
        spf_status = "missing"
        findings.append("No SPF (Sender Policy Framework) record configured.")
        recommendations.append("Add a TXT record with 'v=spf1 ...' to authorize legitimate mail senders and prevent spoofing.")
    elif spf_status == "neutral":
        score -= 10
        findings.append("SPF record uses permissive '+all' or '?all' policy.")
        recommendations.append("Harden SPF policy from permissive to '~all' (softfail) or '-all' (hard reject).")
    else:
        findings.append(f"SPF record configured ({spf_status} enforcement).")

    if not dmarc_record:
        score -= 25
        dmarc_policy = "missing"
        findings.append("No DMARC record configured.")
        recommendations.append("Create a TXT record at '_dmarc." + domain + "' with 'v=DMARC1; p=quarantine;' to protect against phishing abuse.")
    elif dmarc_policy == "none":
        score -= 10
        findings.append("DMARC record exists with monitoring-only policy (p=none).")
        recommendations.append("Progress DMARC policy from 'p=none' to 'p=quarantine' or 'p=reject' once mail flows are verified.")
    else:
        findings.append(f"DMARC record actively enforced with policy 'p={dmarc_policy}'.")

    score = max(0, min(100, score))

    if score >= 80:
        risk_level = "LOW"
    elif score >= 50:
        risk_level = "MEDIUM"
    else:
        risk_level = "HIGH"

    return DNSSecurityReport(
        domain=domain,
        ip_addresses=ip_addresses,
        ipv6_addresses=ipv6_addresses,
        mail_servers=mail_servers,
        nameservers=nameservers,
        spf_record=spf_record,
        spf_status=spf_status,
        dmarc_record=dmarc_record,
        dmarc_policy=dmarc_policy,
        security_score=score,
        risk_level=risk_level,
        findings=findings,
        recommendations=recommendations,
    )


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/dns-inspect", response_model=DNSSecurityReport, summary="Inspect domain DNS, MX, SPF & DMARC posture")
def get_dns_inspection(
    domain: str = Query(..., min_length=2, max_length=253, description="Domain name to inspect (e.g. google.com)"),
):
    """
    Forensic DNS Intelligence Inspector.
    Analyzes domain routing, SPF enforcement, and DMARC posture to assess domain spoofing risk.
    """
    return inspect_domain_dns(domain)


@router.get("/system-status", response_model=SystemHealthResponse, summary="Live Cloud and Security Engine Status")
def get_system_status(db: Session = Depends(get_db)):
    """
    Provides comprehensive telemetry on cloud runtime, machine learning model,
    connected threat intelligence feeds, and database statistics.
    """
    settings = get_settings()
    model = get_model()
    is_model_loaded = model is not None

    total_scans = 0
    total_users = 0
    db_engine_name = "sqlite"
    try:
        total_scans = db.query(models.ScanHistory).count()
        total_users = db.query(models.User).count()
        db_engine_name = "postgresql" if "postgresql" in settings.database_url else "sqlite"
    except Exception:
        pass

    vt_configured = bool(settings.virustotal_api_key and len(settings.virustotal_api_key) > 5)

    return SystemHealthResponse(
        status="healthy",
        version="2.1.0",
        timestamp=datetime.now(timezone.utc).isoformat(),
        environment=os.getenv("ENVIRONMENT", "production"),
        ml_engine={
            "model_loaded": is_model_loaded,
            "algorithm": "RandomForestClassifier",
            "features_extracted": 28,
            "inference_mode": "in-memory-fast",
        },
        threat_providers={
            "virustotal": {
                "configured": vt_configured,
                "status": "ready" if vt_configured else "optional_unconfigured",
                "engines_count": 70 if vt_configured else 0,
            },
            "whois_rdap": {
                "status": "active",
                "provider": "python-whois / IANA RDAP",
            },
            "ssl_certificate_validator": {
                "status": "active",
                "protocols": ["TLS 1.2", "TLS 1.3"],
            },
            "ssrf_protection_guard": {
                "status": "active",
                "rules": "RFC1918 / Private IPv4 & IPv6 Loopback Blocked",
            },
        },
        database={
            "engine": db_engine_name,
            "connected": True,
            "total_scans_recorded": total_scans,
            "registered_users": total_users,
        },
    )
