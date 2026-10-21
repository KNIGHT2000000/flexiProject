"""
Cloud-native analysis endpoint: POST /analyze
Complies with AWS serverless API standards, structured telemetry, and versioned risk reporting.
Preserves interoperability with legacy endpoints.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Optional, Any
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field

from app.database import get_db
from app import models
from app.auth import get_current_user
from app.feature_extractor import extract_features, features_to_vector
from app.url_utils import validate_and_normalize_url, redact_sensitive_url
from app.ssrf_protection import safe_trace_redirects, is_safe_host
from app.risk_engine import aggregate_risk, EvidenceStatus
from app.threat_intel import (
    check_virustotal, check_whois, check_ssl,
    check_typosquatting, capture_screenshot,
)
from app.routers.scan import get_model, _is_whitelisted, _maybe_send_alert


router = APIRouter(tags=["cloud-analysis"])


class AnalyzeRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=2048, description="Target URL string to analyze")
    include_screenshot: bool = Field(False, description="Optionally capture page screenshot if safe")
    include_details: bool = Field(True, description="Include detailed feature extraction in response")


class ProviderStatus(BaseModel):
    ml_model: str = "ok"         # ok | fallback | error
    virustotal: str = "ok"       # ok | unavailable | error
    whois: str = "ok"            # ok | timeout | error | not_applicable
    ssl: str = "ok"              # ok | no_ssl | expired | error


class AnalyzeResponse(BaseModel):
    request_id: str
    url: str
    prediction: str              # legitimate | suspicious | phishing
    risk_score: float            # 0.0 to 100.0
    risk_level: str              # LOW | MEDIUM | HIGH | CRITICAL
    analyzed_at: str
    engine_version: str = "2.1.0"
    features: Optional[dict] = None
    evidence: list[dict] = Field(default_factory=list)
    providers: ProviderStatus
    redirect_chain: list[str] = Field(default_factory=list)
    typosquatting: list[dict] = Field(default_factory=list)
    screenshot: Optional[str] = None
    recommendations: list[str] = Field(default_factory=list)


def _compute_risk_level(score: float) -> str:
    if score >= 80.0:
        return "CRITICAL"
    elif score >= 60.0:
        return "HIGH"
    elif score >= 30.0:
        return "MEDIUM"
    return "LOW"


async def _handle_analysis(
    req: AnalyzeRequest,
    request: Request,
    db: Session,
    current_user=None,
) -> AnalyzeResponse:
    request_id = getattr(request.state, "request_id", "req-unknown")
    analyzed_at = datetime.now(timezone.utc).isoformat()

    # 1. Validation & RFC Normalization
    val = validate_and_normalize_url(req.url)
    if not val.is_valid:
        raise HTTPException(status_code=400, detail=val.error_message or "Invalid URL provided.")

    target_url = val.normalized_url

    # 2. Check Banned Domains
    import tldextract as _tld
    _ext = _tld.extract(target_url)
    _domain = f"{_ext.domain}.{_ext.suffix}".lower() if _ext.domain else val.ascii_hostname
    banned = db.query(models.BannedDomain).filter(models.BannedDomain.domain == _domain).first()
    if banned:
        reason = banned.reason or "Flagged by security administrator"
        return AnalyzeResponse(
            request_id=request_id,
            url=target_url,
            prediction="phishing",
            risk_score=100.0,
            risk_level="CRITICAL",
            analyzed_at=analyzed_at,
            providers=ProviderStatus(ml_model="bypassed", virustotal="bypassed", whois="bypassed", ssl="bypassed"),
            evidence=[{"source": "admin_blacklist", "status": "confirmed_threat", "description": f"Domain banned: {reason}"}],
            recommendations=[f"Domain is on the global ban list: {reason}"],
        )

    # 3. Whitelist Check
    user_id = current_user.id if current_user else None
    if user_id and _is_whitelisted(target_url, db, user_id):
        features = extract_features(target_url) if req.include_details else None
        return AnalyzeResponse(
            request_id=request_id,
            url=target_url,
            prediction="legitimate",
            risk_score=0.0,
            risk_level="LOW",
            analyzed_at=analyzed_at,
            features=features,
            providers=ProviderStatus(ml_model="bypassed", virustotal="bypassed", whois="bypassed", ssl="bypassed"),
            evidence=[{"source": "whitelist", "status": "no_threat_match", "description": "Domain matches user whitelist"}],
            recommendations=["Domain is on your whitelist."],
        )

    # 4. Feature Extraction & Model Inference
    features = extract_features(target_url)
    vector = features_to_vector(features)
    model = get_model()

    # 5. Safe Threat Intelligence Lookups
    vt_result = await check_virustotal(target_url)
    whois_result = check_whois(target_url)
    ssl_result = check_ssl(target_url)
    redirect_chain = await safe_trace_redirects(target_url, max_hops=3, timeout_sec=2.0)
    typosquatting = check_typosquatting(target_url)

    screenshot = None
    if req.include_screenshot:
        safe_host, _ = is_safe_host(val.hostname)
        if safe_host:
            screenshot = await capture_screenshot(target_url)

    # 6. Risk Aggregation
    assessment = aggregate_risk(
        features=features,
        ml_model=model,
        vector=vector,
        validation_result=val,
        virustotal_data=vt_result,
        whois_data=whois_result,
        ssl_data=ssl_result,
        redirect_chain=redirect_chain,
        typosquatting=typosquatting,
    )

    # 7. Map Provider Status
    provider_status = ProviderStatus(
        ml_model="ok" if assessment.ml_prediction else "fallback",
        virustotal="ok" if vt_result.get("available") else ("unavailable" if not vt_result.get("available") else "error"),
        whois="ok" if not whois_result.get("error") else ("timeout" if "timed out" in whois_result.get("error", "").lower() else "error"),
        ssl="ok" if ssl_result.get("has_ssl") and not ssl_result.get("is_expired") else ("expired" if ssl_result.get("is_expired") else "no_ssl"),
    )

    # 8. Record in Scan History (Sanitizing Sensitive Parameters)
    stored_url = redact_sensitive_url(target_url)
    scan = models.ScanHistory(
        url=stored_url,
        prediction=assessment.prediction,
        risk_score=assessment.risk_score,
        features=json.dumps(features),
        virustotal_result=json.dumps(vt_result),
        whois_result=json.dumps(whois_result),
        ssl_result=json.dumps(ssl_result),
        redirect_chain=json.dumps(redirect_chain),
        typosquatting=json.dumps(typosquatting),
        user_id=user_id,
    )
    db.add(scan)
    db.commit()

    if user_id and assessment.risk_score >= 60.0:
        _maybe_send_alert(db, user_id, target_url, assessment.prediction, assessment.risk_score)

    evidence_dicts = [e.model_dump() if hasattr(e, "model_dump") else e.dict() for e in assessment.evidence]

    return AnalyzeResponse(
        request_id=request_id,
        url=target_url,
        prediction=assessment.prediction,
        risk_score=assessment.risk_score,
        risk_level=_compute_risk_level(assessment.risk_score),
        analyzed_at=analyzed_at,
        features=features if req.include_details else None,
        evidence=evidence_dicts,
        providers=provider_status,
        redirect_chain=redirect_chain,
        typosquatting=typosquatting,
        screenshot=screenshot,
        recommendations=assessment.recommendations,
    )


@router.post("/analyze", response_model=AnalyzeResponse, summary="Analyze URL for phishing threats")
async def analyze_url(
    req: AnalyzeRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    return await _handle_analysis(req, request, db, current_user)


@router.post("/api/analyze", response_model=AnalyzeResponse, summary="Analyze URL for phishing threats (API route)")
async def analyze_url_api_alias(
    req: AnalyzeRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    return await _handle_analysis(req, request, db, current_user)
