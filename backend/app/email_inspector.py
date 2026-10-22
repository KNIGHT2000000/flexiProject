"""
PhishGuard Cloud — Advanced Email Phishing & Social Engineering Inspector.
Analyzes email headers, body text, urgency lures, sender spoofing,
and mismatched anchor links.
"""
from __future__ import annotations

import re
from typing import Optional, Any
from pydantic import BaseModel, Field

# Common social engineering patterns in phishing emails
URGENCY_PATTERNS = [
    (r"\b(?:account|access|service)\s+(?:has\s+been\s+|is\s+)?(?:suspended|restricted|disabled|locked|terminated|closed)\b", "Account Suspension Threat", 25.0),
    (r"\b(?:within|in)\s+\d+\s+(?:hours?|mins?|minutes?|days?)\b", "Strict Time Pressure / Artificial Deadline", 20.0),
    (r"\b(?:immediate(?:ly)?|urgent(?:ly)?)\s+(?:action|attention|verification|response)\b", "Urgent Coercion Lure", 20.0),
    (r"\bunauthorized\s+(?:login|activity|transaction|access|attempt|charge)\b", "Security Alarm / Fraud Alert", 20.0),
    (r"\b(?:verify|validate|confirm|update)\s+your\s+(?:identity|account|credentials|password|information|wallet)\b", "Credential Verification Lure", 20.0),
    (r"\b(?:wire\s+transfer|gift\s+card|bitcoin|crypto\s+payment|overdue\s+invoice)\b", "Financial / Wire Payment Request", 15.0),
    (r"\b(?:tax\s+refund|stimulus|lottery|prize|winner|inheritance|unclaimed\s+funds)\b", "Unsolicited Reward / Tax Refund Bait", 15.0),
    (r"\b(?:click\s+here|follow\s+this\s+link|download\s+attachment|scan\s+the\s+qr)\b", "High-Pressure Call to Action", 10.0),
]

SPOOFABLE_BRANDS = [
    "paypal", "apple", "microsoft", "google", "amazon", "netflix",
    "chase", "wellsfargo", "bankofamerica", "citibank", "meta", "facebook",
    "instagram", "dhl", "fedex", "ups", "usps", "steam", "coinbase", "binance",
]


class SenderAnalysis(BaseModel):
    display_name: str = ""
    email_address: str = ""
    reply_to: Optional[str] = None
    is_spoofed: bool = False
    spoof_reason: Optional[str] = None


class MismatchedLink(BaseModel):
    display_text: str
    destination_url: str
    reason: str


class EmailInspectionResult(BaseModel):
    total_urls: int = 0
    scanned_urls: list[dict] = Field(default_factory=list)
    phishing_urls_count: int = 0
    suspicious_urls_count: int = 0
    email_risk_score: float = 0.0
    email_prediction: str = "legitimate"     # legitimate | suspicious | phishing
    lures_detected: list[dict] = Field(default_factory=list)
    sender: SenderAnalysis = Field(default_factory=SenderAnalysis)
    mismatched_links: list[MismatchedLink] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)


def inspect_email(raw_content: str, scanned_url_results: list[dict] = None) -> EmailInspectionResult:
    """
    Comprehensive inspection of email content, headers, urgency indicators,
    and link deception.
    """
    scanned_url_results = scanned_url_results or []
    lures: list[dict] = []
    lure_score = 0.0

    # 1. Detect Social Engineering & Urgency Lures
    for pattern, name, weight in URGENCY_PATTERNS:
        match = re.search(pattern, raw_content, re.IGNORECASE)
        if match:
            lures.append({
                "lure": name,
                "matched_text": match.group(0),
                "weight": weight,
            })
            lure_score += weight

    lure_score = min(lure_score, 60.0)

    # 2. Sender Analysis
    sender = SenderAnalysis()
    from_match = re.search(r"From:\s*\"?([^\"<\r\n]+)\"?\s*<([^>\r\n]+)>", raw_content, re.IGNORECASE)
    if not from_match:
        from_match = re.search(r"From:\s*([^\r\n<]+<[^\r\n>]+>)", raw_content, re.IGNORECASE)

    reply_to_match = re.search(r"Reply-To:\s*\"?([^\"<\r\n]+)\"?\s*<([^>\r\n]+)>", raw_content, re.IGNORECASE)
    if reply_to_match:
        sender.reply_to = reply_to_match.group(2).strip()

    if from_match:
        if len(from_match.groups()) == 2:
            sender.display_name = from_match.group(1).strip()
            sender.email_address = from_match.group(2).strip()
        else:
            sender.email_address = from_match.group(1).strip()

        # Check if display name claims a trusted brand while email domain is not official
        disp_lower = sender.display_name.lower()
        addr_lower = sender.email_address.lower()
        for brand in SPOOFABLE_BRANDS:
            if brand in disp_lower and not addr_lower.endswith(f"@{brand}.com"):
                sender.is_spoofed = True
                sender.spoof_reason = f"Display name impersonates '{brand.capitalize()}' but sender domain '{addr_lower.split('@')[-1]}' is not affiliated."
                break

        # Check Reply-To mismatch
        if sender.reply_to:
            from_domain = addr_lower.split("@")[-1] if "@" in addr_lower else ""
            reply_domain = sender.reply_to.lower().split("@")[-1] if "@" in sender.reply_to else ""
            if from_domain and reply_domain and from_domain != reply_domain:
                sender.is_spoofed = True
                sender.spoof_reason = f"Reply-To domain '{reply_domain}' does not match From domain '{from_domain}'."

    # 3. Detect Mismatched Anchor Links (<a href="evil.com">paypal.com</a>)
    mismatched_links: list[MismatchedLink] = []
    html_links = re.finditer(r"<a\s+[^>]*href=[\"\']([^\"\']+)[\"\'][^>]*>(.*?)</a>", raw_content, re.IGNORECASE | re.DOTALL)
    for m in html_links:
        dest_url = m.group(1).strip()
        disp_text = re.sub(r"<[^>]+>", "", m.group(2)).strip()
        # If display text looks like a URL or well-known domain but destination is different
        if any(d in disp_text.lower() for d in [".com", ".net", ".org", "http://", "https://", "www."]):
            clean_disp = disp_text.lower().replace("http://", "").replace("https://", "").replace("www.", "").strip("/")
            clean_dest = dest_url.lower().replace("http://", "").replace("https://", "").replace("www.", "").strip("/")
            if clean_disp and not clean_dest.startswith(clean_disp.split("/")[0]):
                mismatched_links.append(MismatchedLink(
                    display_text=disp_text,
                    destination_url=dest_url,
                    reason=f"Visible link text pretends to be '{disp_text}' but actually directs to '{dest_url}'.",
                ))

    # 4. Assess Embedded URLs Threat Level
    phish_count = 0
    suspicious_count = 0
    max_url_risk = 0.0
    for u in scanned_url_results:
        pred = u.get("prediction", "legitimate")
        score = u.get("risk_score", 0.0)
        if pred == "phishing" or score >= 60.0:
            phish_count += 1
        elif pred == "suspicious" or score >= 30.0:
            suspicious_count += 1
        if score > max_url_risk:
            max_url_risk = score

    # 5. Calculate Aggregate Email Risk Score
    base_score = max_url_risk
    if phish_count > 0:
        base_score = max(base_score, 85.0 + min(phish_count * 5.0, 15.0))
    elif suspicious_count > 0:
        base_score = max(base_score, 60.0)

    if sender.is_spoofed:
        base_score = min(base_score + 35.0, 100.0)

    if mismatched_links:
        base_score = min(base_score + 40.0, 100.0)

    if lures:
        base_score = min(base_score + (len(lures) * 10.0), 100.0)

    final_email_score = round(min(max(base_score, 0.0), 100.0), 1)
    if final_email_score >= 60.0 or phish_count > 0 or mismatched_links:
        prediction = "phishing"
    elif final_email_score >= 30.0 or suspicious_count > 0 or sender.is_spoofed or len(lures) >= 2:
        prediction = "suspicious"
    else:
        prediction = "legitimate"

    # 6. Generate Actionable Recommendations
    recs: list[str] = []
    if prediction == "phishing":
        recs.append("CRITICAL: This email shows high-confidence phishing indicators. Do not click links, reply, or enter credentials.")
    elif prediction == "suspicious":
        recs.append("WARNING: This email contains suspicious lures or unverified links. Verify through official channels.")

    if sender.is_spoofed and sender.spoof_reason:
        recs.append(sender.spoof_reason)

    if mismatched_links:
        recs.append("Deceptive hyperlink detected: visible text does not match real destination URL.")

    for l in lures[:3]:
        recs.append(f"Psychological trigger detected: {l['lure']}.")

    if not recs:
        recs.append("No overt phishing patterns detected in email headers or text. Continue practicing standard cyber hygiene.")

    return EmailInspectionResult(
        total_urls=len(scanned_url_results),
        scanned_urls=scanned_url_results,
        phishing_urls_count=phish_count,
        suspicious_urls_count=suspicious_count,
        email_risk_score=final_email_score,
        email_prediction=prediction,
        lures_detected=lures,
        sender=sender,
        mismatched_links=mismatched_links,
        recommendations=recs,
    )
