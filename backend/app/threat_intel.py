import httpx
import socket
import ssl
import whois
import difflib
from datetime import datetime, timezone
from urllib.parse import urlparse
from typing import Optional
from app.config import get_settings

settings = get_settings()

# Top brands to check for typosquatting
POPULAR_BRANDS = [
    "google", "facebook", "amazon", "apple", "microsoft", "paypal",
    "netflix", "instagram", "twitter", "linkedin", "youtube", "github",
    "dropbox", "spotify", "ebay", "yahoo", "adobe", "chase", "wellsfargo",
    "bankofamerica", "citibank", "steam", "roblox", "discord", "tiktok",
]


async def check_virustotal(url: str) -> Optional[dict]:
    if not settings.virustotal_api_key:
        return {"error": "VirusTotal API key not configured", "available": False}

    headers = {"x-apikey": settings.virustotal_api_key}
    async with httpx.AsyncClient(timeout=15) as client:
        try:
            resp = await client.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data={"url": url},
            )
            if resp.status_code not in (200, 201):
                return {"error": f"VT submission failed: {resp.status_code}", "available": True}

            analysis_id = resp.json().get("data", {}).get("id", "")
            if not analysis_id:
                return {"error": "No analysis ID returned", "available": True}

            result_resp = await client.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=headers,
            )
            data = result_resp.json().get("data", {}).get("attributes", {})
            stats = data.get("stats", {})
            return {
                "available": True,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "status": data.get("status", "unknown"),
            }
        except Exception as e:
            return {"error": str(e), "available": True}


def check_whois(url: str) -> dict:
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.replace("www.", "").split(":")[0]
        if not domain:
            return {"error": "Empty domain", "domain": ""}

        # Avoid hanging on raw IP addresses or localhost
        import ipaddress
        try:
            ipaddress.ip_address(domain)
            return {"error": "WHOIS lookup not applicable for raw IP addresses", "domain": domain}
        except ValueError:
            pass

        if "." not in domain or domain.endswith(".local") or domain == "localhost":
            return {"error": "WHOIS lookup not applicable for non-public domains", "domain": domain}

        # Set bounded socket timeout to avoid hanging for 15+ seconds
        orig_timeout = socket.getdefaulttimeout()
        try:
            socket.setdefaulttimeout(3.5)
            w = whois.whois(domain)
        finally:
            socket.setdefaulttimeout(orig_timeout)

        creation = w.creation_date
        expiry = w.expiration_date
        if isinstance(creation, list):
            creation = creation[0]
        if isinstance(expiry, list):
            expiry = expiry[0]

        now_utc = datetime.now(timezone.utc)
        domain_age_days = None
        if creation:
            # Normalize to naive UTC for safe arithmetic if creation has tz or not
            c_naive = creation.replace(tzinfo=None) if hasattr(creation, "tzinfo") and creation.tzinfo else creation
            domain_age_days = (now_utc.replace(tzinfo=None) - c_naive).days

        return {
            "domain": domain,
            "registrar": getattr(w, "registrar", None),
            "creation_date": creation.isoformat() if creation else None,
            "expiry_date": expiry.isoformat() if expiry else None,
            "domain_age_days": domain_age_days,
            "is_new_domain": domain_age_days is not None and domain_age_days < 180,
            "country": getattr(w, "country", None),
            "org": getattr(w, "org", None),
        }
    except Exception as e:
        return {"error": str(e), "domain": urlparse(url).netloc}


def check_ssl(url: str) -> dict:
    try:
        parsed = urlparse(url)
        hostname = parsed.netloc.split(":")[0]

        if parsed.scheme != "https":
            return {"has_ssl": False, "error": "URL does not use HTTPS"}

        if not hostname:
            return {"has_ssl": False, "error": "No hostname found"}

        # Prevent connecting to internal/private addresses
        from app.ssrf_protection import is_safe_host
        safe, reason = is_safe_host(hostname)
        if not safe:
            return {"has_ssl": False, "error": f"Target host blocked by SSRF firewall: {reason}"}

        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(4.0)
            s.connect((hostname, 443))
            cert = s.getpeercert()

        not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
        now_naive = datetime.now(timezone.utc).replace(tzinfo=None)
        days_left = (not_after - now_naive).days
        issuer = dict(x[0] for x in cert.get("issuer", []))
        subject = dict(x[0] for x in cert.get("subject", []))

        return {
            "has_ssl": True,
            "issuer": issuer.get("organizationName", "Unknown"),
            "subject": subject.get("commonName", hostname),
            "valid_from": not_before.isoformat(),
            "valid_until": not_after.isoformat(),
            "days_remaining": days_left,
            "is_expired": days_left < 0,
            "is_expiring_soon": 0 <= days_left <= 30,
        }
    except ssl.SSLCertVerificationError as e:
        return {"has_ssl": True, "valid": False, "error": f"SSL verification failed: {str(e)}"}
    except Exception as e:
        return {"has_ssl": False, "error": str(e)}


async def trace_redirects(url: str) -> list[str]:
    """Safe redirect tracing delegated to SSRF-protected tracer."""
    from app.ssrf_protection import safe_trace_redirects
    return await safe_trace_redirects(url, max_hops=3, timeout_sec=2.0)


def check_typosquatting(url: str) -> list[dict]:
    """Compare the domain against popular brands for typosquatting."""
    parsed = urlparse(url)
    import tldextract
    ext = tldextract.extract(url)
    domain_name = ext.domain.lower()

    matches = []
    for brand in POPULAR_BRANDS:
        if domain_name == brand:
            continue  # exact match — it IS the brand
        ratio = difflib.SequenceMatcher(None, domain_name, brand).ratio()
        if ratio >= 0.75:
            matches.append({"brand": brand, "similarity": round(ratio * 100, 1)})

    return sorted(matches, key=lambda x: -x["similarity"])


async def capture_screenshot(url: str) -> Optional[str]:
    """Capture a base64 screenshot of the URL using Playwright (headless)."""
    try:
        from playwright.async_api import async_playwright
        import base64
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True, args=["--no-sandbox"])
            page = await browser.new_page(viewport={"width": 1280, "height": 720})
            await page.goto(url, timeout=15000, wait_until="domcontentloaded")
            screenshot = await page.screenshot(type="jpeg", quality=70, full_page=False)
            await browser.close()
            return base64.b64encode(screenshot).decode()
    except Exception as e:
        return None


def generate_recommendations(
    prediction: str,
    risk_score: float,
    features: dict,
    whois_data: dict,
    ssl_data: dict,
    redirect_chain: list = None,
    typosquatting: list = None,
) -> list:
    recs = []

    if prediction == "phishing":
        recs.append("Do NOT visit this URL. It is classified as a phishing site.")
    elif prediction == "suspicious":
        recs.append("Exercise extreme caution. This URL shows multiple suspicious indicators.")

    if features.get("uses_https") == 0:
        recs.append("This site does not use HTTPS. Avoid entering sensitive information.")
    if features.get("has_ip_address"):
        recs.append("URL uses an IP address instead of a domain — a common phishing tactic.")
    if features.get("has_at_symbol"):
        recs.append("URL contains '@' which can disguise the real destination.")
    if features.get("has_suspicious_keywords", 0) > 2:
        recs.append("URL contains multiple suspicious keywords commonly used in phishing.")
    if whois_data and whois_data.get("is_new_domain"):
        recs.append(
            f"Domain is only {whois_data.get('domain_age_days')} days old. "
            "Newly registered domains are frequently used in phishing attacks."
        )
    if ssl_data:
        if ssl_data.get("is_expired"):
            recs.append("SSL certificate is expired.")
        if not ssl_data.get("has_ssl"):
            recs.append("No valid SSL certificate detected.")
    if redirect_chain and len(redirect_chain) > 2:
        recs.append(
            f"URL redirects through {len(redirect_chain) - 1} hops — "
            "multi-hop redirects are a common phishing obfuscation technique."
        )
    if typosquatting:
        brands = ", ".join(t["brand"] for t in typosquatting[:3])
        recs.append(f"Domain looks similar to well-known brand(s): {brands}. Possible typosquatting.")

    if not recs:
        recs.append("No immediate threats detected. Always stay vigilant online.")

    return recs
