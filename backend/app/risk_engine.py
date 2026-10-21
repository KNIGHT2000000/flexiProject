"""
Transparent Risk Assessment and Evidence Aggregation Layer.
Combines Machine Learning, heuristic signals, domain reputation, and SSL certificates
into a calibrated, versioned risk score and verdict without double-counting.
"""
from __future__ import annotations

from enum import Enum
from typing import Optional, Any
from pydantic import BaseModel, Field
import numpy as np


class EvidenceStatus(str, Enum):
    CONFIRMED_THREAT = "confirmed_threat"
    SUSPICIOUS_HEURISTIC = "suspicious_heuristic"
    NO_THREAT_MATCH = "no_threat_match"
    PROVIDER_ERROR = "provider_error"
    INCOMPLETE_ANALYSIS = "incomplete_analysis"


class EvidenceItem(BaseModel):
    source: str
    status: EvidenceStatus
    description: str
    weight: float = 0.0
    details: dict[str, Any] = Field(default_factory=dict)


class AggregatedRiskAssessment(BaseModel):
    prediction: str                      # "legitimate" | "suspicious" | "phishing"
    risk_score: float                    # 0.0 to 100.0
    engine_version: str = "2.1.0"
    ml_prediction: Optional[str] = None
    ml_risk_score: Optional[float] = None
    heuristic_score: float = 0.0
    evidence: list[EvidenceItem] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)


def evaluate_heuristics(features: dict, validation_result=None) -> tuple[str, float, list[EvidenceItem]]:
    """
    Transparent rule-based heuristic scoring based on URL features.
    Treats heuristics as evidence, not absolute proof.
    """
    score = 0.0
    evidence: list[EvidenceItem] = []

    if features.get("has_ip_address"):
        score += 30.0
        evidence.append(EvidenceItem(
            source="heuristics.ip_address",
            status=EvidenceStatus.SUSPICIOUS_HEURISTIC,
            description="URL uses raw IP address instead of domain name",
            weight=30.0,
        ))

    if features.get("has_at_symbol"):
        score += 20.0
        evidence.append(EvidenceItem(
            source="heuristics.at_symbol",
            status=EvidenceStatus.SUSPICIOUS_HEURISTIC,
            description="URL contains '@' symbol (authority credential disguise trick)",
            weight=20.0,
        ))

    if not features.get("uses_https"):
        score += 15.0
        evidence.append(EvidenceItem(
            source="heuristics.protocol",
            status=EvidenceStatus.SUSPICIOUS_HEURISTIC,
            description="URL does not use HTTPS",
            weight=15.0,
        ))

    kw_count = features.get("has_suspicious_keywords", 0)
    if kw_count > 0:
        kw_weight = min(kw_count * 8.0, 24.0)
        score += kw_weight
        evidence.append(EvidenceItem(
            source="heuristics.keywords",
            status=EvidenceStatus.SUSPICIOUS_HEURISTIC,
            description=f"Contains {kw_count} high-risk security keyword(s)",
            weight=kw_weight,
        ))

    if features.get("has_suspicious_tld"):
        score += 20.0
        evidence.append(EvidenceItem(
            source="heuristics.tld",
            status=EvidenceStatus.SUSPICIOUS_HEURISTIC,
            description="URL uses a high-abuse top-level domain (.tk, .ml, .xyz, etc.)",
            weight=20.0,
        ))

    if features.get("num_dots", 0) > 5:
        score += 10.0
        evidence.append(EvidenceItem(
            source="heuristics.excessive_dots",
            status=EvidenceStatus.SUSPICIOUS_HEURISTIC,
            description="Excessive dot count (>5) in URL",
            weight=10.0,
        ))

    if features.get("has_hyphen_in_domain"):
        score += 10.0
        evidence.append(EvidenceItem(
            source="heuristics.hyphen_domain",
            status=EvidenceStatus.SUSPICIOUS_HEURISTIC,
            description="Domain contains hyphens commonly used in brand spoofing",
            weight=10.0,
        ))

    if features.get("has_hex_encoding"):
        score += 15.0
        evidence.append(EvidenceItem(
            source="heuristics.hex_encoding",
            status=EvidenceStatus.SUSPICIOUS_HEURISTIC,
            description="URL path contains hex/percent encoding obfuscation",
            weight=15.0,
        ))

    if features.get("has_punycode"):
        score += 20.0
        evidence.append(EvidenceItem(
            source="heuristics.punycode",
            status=EvidenceStatus.SUSPICIOUS_HEURISTIC,
            description="Internationalized domain using Punycode (xn--)",
            weight=20.0,
        ))

    if features.get("has_non_standard_port"):
        score += 15.0
        evidence.append(EvidenceItem(
            source="heuristics.port",
            status=EvidenceStatus.SUSPICIOUS_HEURISTIC,
            description="URL explicitly targets a non-standard port",
            weight=15.0,
        ))

    if validation_result and getattr(validation_result, "has_homoglyphs", False):
        score += 25.0
        evidence.append(EvidenceItem(
            source="heuristics.homoglyphs",
            status=EvidenceStatus.SUSPICIOUS_HEURISTIC,
            description="Domain contains visual homoglyphs (Cyrillic/Greek character substitution)",
            weight=25.0,
        ))

    capped_score = min(score, 100.0)
    pred = "phishing" if capped_score >= 60.0 else "suspicious" if capped_score >= 30.0 else "legitimate"
    return pred, round(capped_score, 1), evidence


def aggregate_risk(
    features: dict,
    ml_model=None,
    vector: list = None,
    validation_result=None,
    virustotal_data: Optional[dict] = None,
    whois_data: Optional[dict] = None,
    ssl_data: Optional[dict] = None,
    redirect_chain: Optional[list[str]] = None,
    typosquatting: Optional[list[dict]] = None,
    is_whitelisted: bool = False,
    banned_reason: Optional[str] = None,
) -> AggregatedRiskAssessment:
    """
    Synthesize ML inference, heuristic evidence, and external threat intel
    into a calibrated, robust verdict.
    """
    evidence: list[EvidenceItem] = []
    recs: list[str] = []

    # 1. Whitelist override
    if is_whitelisted:
        evidence.append(EvidenceItem(
            source="whitelist",
            status=EvidenceStatus.NO_THREAT_MATCH,
            description="Domain matches user-defined trusted whitelist",
            weight=0.0,
        ))
        recs.append("Domain is on your whitelist.")
        return AggregatedRiskAssessment(
            prediction="legitimate",
            risk_score=0.0,
            evidence=evidence,
            recommendations=recs,
        )

    # 2. Banned domain override
    if banned_reason is not None:
        evidence.append(EvidenceItem(
            source="admin_blacklist",
            status=EvidenceStatus.CONFIRMED_THREAT,
            description=f"Domain is on the global banned list: {banned_reason}",
            weight=100.0,
        ))
        recs.append(f"Domain is on the global ban list: {banned_reason}")
        return AggregatedRiskAssessment(
            prediction="phishing",
            risk_score=100.0,
            evidence=evidence,
            recommendations=recs,
        )

    # 3. Base Heuristics
    heuristic_pred, heuristic_score, heuristic_evidence = evaluate_heuristics(features, validation_result)
    evidence.extend(heuristic_evidence)

    # 4. ML Model Inference
    ml_pred = None
    ml_risk_score = None
    if ml_model and vector is not None:
        try:
            proba = ml_model.predict_proba([vector])[0]
            pred_class = int(np.argmax(proba))
            label_map = {0: "legitimate", 1: "suspicious", 2: "phishing"}
            ml_pred = label_map[pred_class]
            ml_risk_score = round(float(proba[1] * 0.5 + proba[2]) * 100, 1)

            evidence.append(EvidenceItem(
                source="ml_random_forest",
                status=EvidenceStatus.CONFIRMED_THREAT if ml_pred == "phishing" else (
                    EvidenceStatus.SUSPICIOUS_HEURISTIC if ml_pred == "suspicious" else EvidenceStatus.NO_THREAT_MATCH
                ),
                description=f"Random Forest model classified as {ml_pred} (ML risk: {ml_risk_score}%)",
                weight=ml_risk_score,
                details={"probabilities": proba.tolist()},
            ))
            final_score = ml_risk_score
        except Exception as e:
            evidence.append(EvidenceItem(
                source="ml_random_forest",
                status=EvidenceStatus.PROVIDER_ERROR,
                description=f"ML inference error: {e}",
            ))
            final_score = heuristic_score
    else:
        final_score = heuristic_score

    # 5. Threat Intelligence: VirusTotal
    if virustotal_data:
        if virustotal_data.get("available"):
            malicious = virustotal_data.get("malicious", 0)
            suspicious = virustotal_data.get("suspicious", 0)
            if malicious > 0:
                vt_boost = 90.0 + min(float(malicious) * 2.0, 10.0)
                final_score = max(final_score, vt_boost)
                evidence.append(EvidenceItem(
                    source="threat_intel.virustotal",
                    status=EvidenceStatus.CONFIRMED_THREAT,
                    description=f"VirusTotal detected {malicious} security vendors flagging this URL as malicious",
                    weight=vt_boost,
                    details=virustotal_data,
                ))
            elif suspicious > 0:
                final_score = max(final_score, 65.0)
                evidence.append(EvidenceItem(
                    source="threat_intel.virustotal",
                    status=EvidenceStatus.SUSPICIOUS_HEURISTIC,
                    description=f"VirusTotal reported {suspicious} vendor(s) flagging as suspicious",
                    weight=65.0,
                    details=virustotal_data,
                ))
            else:
                evidence.append(EvidenceItem(
                    source="threat_intel.virustotal",
                    status=EvidenceStatus.NO_THREAT_MATCH,
                    description="No threat engines on VirusTotal reported this URL as malicious",
                    details=virustotal_data,
                ))
        elif "error" in virustotal_data:
            evidence.append(EvidenceItem(
                source="threat_intel.virustotal",
                status=EvidenceStatus.PROVIDER_ERROR,
                description=f"VirusTotal unavailable: {virustotal_data.get('error')}",
            ))

    # 6. Domain Age (WHOIS / RDAP)
    if whois_data:
        if whois_data.get("is_new_domain"):
            days = whois_data.get("domain_age_days")
            final_score = min(final_score + 15.0, 100.0)
            evidence.append(EvidenceItem(
                source="threat_intel.whois",
                status=EvidenceStatus.SUSPICIOUS_HEURISTIC,
                description=f"Newly registered domain ({days} days old)",
                weight=15.0,
                details={"domain_age_days": days},
            ))
        elif "error" in whois_data:
            evidence.append(EvidenceItem(
                source="threat_intel.whois",
                status=EvidenceStatus.PROVIDER_ERROR,
                description=f"WHOIS lookup failed or timed out: {whois_data.get('error')}",
            ))

    # 7. SSL Validation
    if ssl_data:
        if ssl_data.get("is_expired"):
            final_score = min(final_score + 20.0, 100.0)
            evidence.append(EvidenceItem(
                source="threat_intel.ssl",
                status=EvidenceStatus.SUSPICIOUS_HEURISTIC,
                description="SSL certificate is expired",
                weight=20.0,
            ))
        elif not ssl_data.get("has_ssl") and features.get("uses_https"):
            final_score = min(final_score + 15.0, 100.0)
            evidence.append(EvidenceItem(
                source="threat_intel.ssl",
                status=EvidenceStatus.SUSPICIOUS_HEURISTIC,
                description=f"SSL certificate check failed: {ssl_data.get('error', 'No SSL')}",
                weight=15.0,
            ))

    # 8. Typosquatting Matches
    if typosquatting:
        top_match = typosquatting[0]
        final_score = min(final_score + 15.0, 100.0)
        evidence.append(EvidenceItem(
            source="threat_intel.typosquatting",
            status=EvidenceStatus.SUSPICIOUS_HEURISTIC,
            description=f"Domain closely resembles brand '{top_match.get('brand')}' ({top_match.get('similarity')}% similarity)",
            weight=15.0,
            details=top_match,
        ))

    final_score = round(min(max(final_score, 0.0), 100.0), 1)
    prediction = "phishing" if final_score >= 60.0 else "suspicious" if final_score >= 30.0 else "legitimate"

    # Recommendations synthesis
    if prediction == "phishing":
        recs.append("Do NOT visit this URL. It is classified as a phishing site.")
    elif prediction == "suspicious":
        recs.append("Exercise extreme caution. This URL shows multiple suspicious indicators.")

    for item in evidence:
        if item.status in (EvidenceStatus.CONFIRMED_THREAT, EvidenceStatus.SUSPICIOUS_HEURISTIC):
            if item.description not in recs:
                recs.append(item.description)

    if not recs:
        recs.append("No immediate threats detected. Always stay vigilant online.")

    return AggregatedRiskAssessment(
        prediction=prediction,
        risk_score=final_score,
        ml_prediction=ml_pred,
        ml_risk_score=ml_risk_score,
        heuristic_score=heuristic_score,
        evidence=evidence,
        recommendations=recs,
    )
