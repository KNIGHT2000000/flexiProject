import httpx
import socket
import ssl
import whois
import difflib
import math
import re
from collections import Counter
from datetime import datetime, timezone
from urllib.parse import urlparse
from typing import Optional
from app.config import get_settings

settings = get_settings()

# Top brands catalog for typosquatting and brand camouflage shielding
KNOWN_BRANDS_CATALOG = {
    "paypal": {"official": ["paypal.com"], "aliases": ["paypal"]},
    "apple": {"official": ["apple.com", "icloud.com"], "aliases": ["apple", "appleid", "icloud"]},
    "microsoft": {"official": ["microsoft.com", "live.com", "office.com", "outlook.com"], "aliases": ["microsoft", "office365", "outlook", "msn"]},
    "google": {"official": ["google.com", "gmail.com", "youtube.com"], "aliases": ["google", "gmail"]},
    "amazon": {"official": ["amazon.com", "aws.amazon.com"], "aliases": ["amazon", "primevideo"]},
    "netflix": {"official": ["netflix.com"], "aliases": ["netflix"]},
    "chase": {"official": ["chase.com"], "aliases": ["chase", "chasebank"]},
    "wellsfargo": {"official": ["wellsfargo.com"], "aliases": ["wellsfargo"]},
    "bankofamerica": {"official": ["bankofamerica.com", "bofa.com"], "aliases": ["bankofamerica", "bofa"]},
    "citibank": {"official": ["citi.com", "citibank.com"], "aliases": ["citibank", "citi"]},
    "facebook": {"official": ["facebook.com", "meta.com", "instagram.com", "whatsapp.com"], "aliases": ["facebook", "instagram", "whatsapp", "meta"]},
    "steam": {"official": ["steampowered.com", "steamcommunity.com"], "aliases": ["steam", "steamcommunity"]},
    "binance": {"official": ["binance.com"], "aliases": ["binance"]},
    "coinbase": {"official": ["coinbase.com"], "aliases": ["coinbase"]},
    "ebay": {"official": ["ebay.com"], "aliases": ["ebay"]},
    "spotify": {"official": ["spotify.com"], "aliases": ["spotify"]},
    "twitter": {"official": ["twitter.com", "x.com"], "aliases": ["twitter"]},
    "linkedin": {"official": ["linkedin.com"], "aliases": ["linkedin"]},
    "dhl": {"official": ["dhl.com"], "aliases": ["dhl"]},
    "fedex": {"official": ["fedex.com"], "aliases": ["fedex"]},
    "ups": {"official": ["ups.com"], "aliases": ["ups"]},
    "usps": {"official": ["usps.com"], "aliases": ["usps"]},
    "discord": {"official": ["discord.com", "discord.gg"], "aliases": ["discord"]},
}

POPULAR_BRANDS = list(KNOWN_BRANDS_CATALOG.keys())

# Free/ephemeral hosting platforms frequently exploited for rapid phishing deployment
FREE_HOSTING_DOMAINS = {
    "duckdns.org", "ngrok.io", "ngrok-free.app", "firebaseapp.com", "web.app",
    "pages.dev", "workers.dev", "vercel.app", "netlify.app", "github.io",
    "gitlab.io", "glitch.me", "000webhostapp.com", "onrender.com", "surge.sh",
    "loca.lt", "repl.co", "supabase.co", "weeblysite.com", "wixsite.com",
}

# Known URL shortener services used to obfuscate destinations
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "cutt.ly", "is.gd", "rb.gy", "ow.ly",
    "buff.ly", "shorturl.at", "tiny.cc", "rebrand.ly", "goo.gl", "clck.ru",
    "v.gd", "soo.gd", "s.id", "trib.al",
}


def detect_dga_and_invalid_tld(url: str) -> dict:
    """
    Detect Domain Generation Algorithm (DGA) entropy, consonant clustering,
    deceptive internal subdomain labels (.com.attacker), and invalid/non-ICANN TLDs.
    """
    import tldextract
    ext = tldextract.extract(url)
    domain = ext.domain.lower() if ext.domain else ""
    suffix = ext.suffix.lower() if ext.suffix else ""
    subdomain = ext.subdomain.lower() if ext.subdomain else ""

    # Check 1: Non-existent / unregistered TLD
    is_invalid_tld = False
    if not suffix and "." in url:
        is_invalid_tld = True

    # Check 2: Deceptive .com or .net inside internal subdomain labels
    deceptive_subdomain = False
    sub_parts = subdomain.split(".")
    if any(part in {"com", "net", "org", "gov", "edu", "co", "io"} for part in sub_parts):
        deceptive_subdomain = True

    # Check 3: Check all hostname labels (domain and subdomains) for consonant clustering & entropy
    full_host = f"{subdomain}.{domain}.{suffix}".strip(".").lower()
    labels = [p for p in re.split(r"[-._]", full_host) if p]

    is_dga_gibberish = False
    dga_reason = ""
    max_consonants = 0
    worst_vowel_ratio = 1.0
    highest_entropy = 0.0

    for label in labels:
        alpha_chars = [c for c in label if c.isalpha()]
        vowel_count = sum(1 for c in alpha_chars if c in "aeiou")
        vowel_ratio = (vowel_count / len(alpha_chars)) if alpha_chars else 1.0
        consonant_matches = re.findall(r"[bcdfghjklmnpqrstvwxyz]+", label)
        consonants_len = max((len(c) for c in consonant_matches), default=0)

        entropy = 0.0
        if len(label) >= 6:
            counts = Counter(label)
            n = len(label)
            entropy = -sum((c / n) * math.log2(c / n) for c in counts.values())

        if consonants_len > max_consonants:
            max_consonants = consonants_len
        if vowel_ratio < worst_vowel_ratio:
            worst_vowel_ratio = vowel_ratio
        if entropy > highest_entropy:
            highest_entropy = entropy

        if len(label) >= 8 and (vowel_ratio < 0.12 or consonants_len >= 6):
            is_dga_gibberish = True
            dga_reason = f"Label '{label}' has unnatural consonant clustering ({consonants_len} consecutive consonants, {round(vowel_ratio * 100)}% vowels)"
            break
        elif len(label) >= 12 and entropy >= 3.6:
            is_dga_gibberish = True
            dga_reason = f"Label '{label}' has excessively high random Shannon entropy ({round(entropy, 2)})"
            break

    return {
        "is_dga_gibberish": is_dga_gibberish,
        "dga_reason": dga_reason,
        "is_invalid_tld": is_invalid_tld,
        "deceptive_subdomain": deceptive_subdomain,
        "max_consonants": max_consonants,
        "vowel_ratio": round(worst_vowel_ratio, 2),
        "entropy": round(highest_entropy, 2),
        "suffix": suffix,
        "domain": domain,
    }


def detect_brand_camouflage(url: str) -> list[dict]:
    """
    Brand Camouflage Shield:
    Identifies unauthorized domains or subdomains spoofing trusted global brands.
    """
    import tldextract
    ext = tldextract.extract(url)
    registered_domain = f"{ext.domain}.{ext.suffix}".lower()
    subdomain = ext.subdomain.lower() if ext.subdomain else ""
    full_host = f"{subdomain}.{ext.domain}.{ext.suffix}".strip(".").lower()

    findings = []
    for brand, info in KNOWN_BRANDS_CATALOG.items():
        official_domains = info["official"]
        # If this is the legitimate brand domain, skip
        if any(registered_domain == off or full_host.endswith("." + off) for off in official_domains):
            continue

        for alias in info["aliases"]:
            # Check 1: Brand keyword embedded in registered domain (e.g. paypal-security, login-apple)
            if alias in ext.domain.lower():
                findings.append({
                    "brand": brand,
                    "type": "unauthorized_brand_domain",
                    "description": f"Domain '{ext.domain}' contains trademark brand '{brand}' without authorization.",
                })
                break
            # Check 2: Brand keyword inside subdomain (e.g. paypal.com.attacker.xyz)
            sub_tokens = [s for s in re.split(r"[-._]", subdomain) if s]
            if alias in sub_tokens:
                findings.append({
                    "brand": brand,
                    "type": "brand_in_subdomain",
                    "description": f"Subdomain '{subdomain}' deceptively includes brand name '{brand}'.",
                })
                break
            # Check 3: Typo / Character substitution (e.g. paypa1, arnazon)
            ratio = difflib.SequenceMatcher(None, ext.domain.lower(), alias).ratio()
            if 0.75 <= ratio < 1.0:
                findings.append({
                    "brand": brand,
                    "type": "typosquatting",
                    "similarity": round(ratio * 100, 1),
                    "description": f"Domain '{ext.domain}' is visually similar to '{brand}' ({round(ratio * 100, 1)}% match).",
                })
                break
    return findings


def detect_free_hosting_abuse(url: str) -> Optional[dict]:
    """
    Identifies free/ephemeral hosting abuse hosting sensitive authentication paths.
    """
    import tldextract
    from urllib.parse import urlparse
    ext = tldextract.extract(url)
    parsed = urlparse(url)
    registered_domain = f"{ext.domain}.{ext.suffix}".lower()

    if registered_domain in FREE_HOSTING_DOMAINS:
        path = parsed.path.lower()
        subdomain = ext.subdomain.lower() if ext.subdomain else ""
        sensitive_keywords = [
            "login", "signin", "verify", "account", "update", "secure",
            "bank", "wallet", "billing", "password", "confirm", "auth", "credential",
        ]
        has_sensitive_path = any(kw in path for kw in sensitive_keywords)
        has_brand_subdomain = any(b in subdomain for b in ["paypal", "apple", "microsoft", "google", "netflix", "chase", "amazon"])
        if has_sensitive_path or has_brand_subdomain:
            return {
                "provider": registered_domain,
                "has_sensitive_path": has_sensitive_path,
                "has_brand_subdomain": has_brand_subdomain,
                "description": f"Free hosting provider '{registered_domain}' is hosting a sensitive credential/login path, a common technique for zero-cost disposable phishing.",
            }
    return None


def detect_url_shortener(url: str) -> Optional[dict]:
    """Detects whether URL belongs to a shortener used to conceal destinations."""
    import tldextract
    ext = tldextract.extract(url)
    registered_domain = f"{ext.domain}.{ext.suffix}".lower()
    if registered_domain in URL_SHORTENERS:
        return {
            "provider": registered_domain,
            "description": f"URL uses shortener service '{registered_domain}' to conceal destination. Exercise caution before visiting.",
        }
    return None


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


async def check_google_safe_browsing(url: str) -> Optional[dict]:
    """Check target URL against Google Safe Browsing / Google Threat Intelligence v4 API."""
    if not settings.google_safe_browsing_api_key:
        return {"available": False, "error": "Google Safe Browsing API key not configured"}

    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={settings.google_safe_browsing_api_key}"
    payload = {
        "client": {"clientId": "phishguard", "clientVersion": "2.1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    async with httpx.AsyncClient(timeout=4.0) as client:
        try:
            resp = await client.post(endpoint, json=payload)
            if resp.status_code == 200:
                data = resp.json()
                matches = data.get("matches", [])
                if matches:
                    threat_types = list(set(m.get("threatType", "MALICIOUS") for m in matches))
                    return {
                        "available": True,
                        "is_threat": True,
                        "threat_types": threat_types,
                        "details": f"Flagged by Google Threat Intelligence: {', '.join(threat_types)}",
                    }
                return {"available": True, "is_threat": False, "details": "Clean in Google Safe Browsing"}
            return {"available": False, "error": f"Google Safe Browsing HTTP {resp.status_code}"}
        except Exception as e:
            return {"available": False, "error": str(e)}


def check_rdap(domain: str) -> Optional[dict]:
    """Fallback domain registration lookup via public IANA/ICANN RDAP (HTTPS port 443, zero API keys required)."""
    try:
        import urllib.request
        import json
        req = urllib.request.Request(
            f"https://rdap.org/domain/{domain}",
            headers={"User-Agent": "PhishGuard-RDAP/2.1", "Accept": "application/rdap+json"}
        )
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", [])}
            reg_date = events.get("registration") or events.get("created")
            exp_date = events.get("expiration")
            now = datetime.now(timezone.utc)
            age_days = None
            if reg_date:
                try:
                    dt = datetime.fromisoformat(reg_date.replace("Z", "+00:00"))
                    age_days = (now - dt).days
                except Exception:
                    pass
            registrar_name = None
            for ent in data.get("entities", []):
                if "registrar" in ent.get("roles", []):
                    vcard = ent.get("vcardArray", [])
                    if len(vcard) > 1:
                        for prop in vcard[1]:
                            if prop[0] == "fn":
                                registrar_name = prop[3]
            return {
                "domain": domain,
                "registrar": registrar_name or data.get("port43", "Unknown Registrar"),
                "creation_date": reg_date,
                "expiry_date": exp_date,
                "domain_age_days": age_days,
                "is_new_domain": age_days is not None and age_days < 180,
            }
    except Exception:
        return None


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
        # Fallback to public HTTPS RDAP if port 43 WHOIS failed or timed out
        try:
            rdap_res = check_rdap(domain)
            if rdap_res:
                return rdap_res
        except Exception:
            pass
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
    return detect_brand_camouflage(url)


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
    except Exception:
        return None


def generate_recommendations(
    prediction: str,
    risk_score: float,
    features: dict,
    whois_data: dict,
    ssl_data: dict,
    redirect_chain: list = None,
    typosquatting: list = None,
    brand_camouflage: list = None,
    free_hosting: dict = None,
    dga_data: dict = None,
    shortener_data: dict = None,
) -> list:
    recs = []

    if prediction == "phishing":
        recs.append("Do NOT visit this URL. It is classified as a phishing site.")
    elif prediction == "suspicious":
        recs.append("Exercise extreme caution. This URL shows multiple suspicious indicators.")

    if brand_camouflage:
        for b in brand_camouflage:
            recs.append(b.get("description", f"Brand spoofing detected targeting {b.get('brand')}."))

    if dga_data:
        if dga_data.get("is_dga_gibberish"):
            recs.append(f"Domain indicates algorithmic generation (DGA) or keyboard mash: {dga_data.get('dga_reason')}.")
        if dga_data.get("is_invalid_tld"):
            recs.append("Domain has an unrecognized or invalid top-level domain (TLD).")
        if dga_data.get("deceptive_subdomain"):
            recs.append("URL contains deceptive domain labels (.com/.net) within subdomains to mislead users.")

    if free_hosting:
        recs.append(free_hosting.get("description", "Disposable free hosting provider used with sensitive path."))

    if shortener_data:
        recs.append(shortener_data.get("description", "URL shortener detected."))

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
    if typosquatting and not brand_camouflage:
        brands = ", ".join(t.get("brand", "brand") for t in typosquatting[:3])
        recs.append(f"Domain looks similar to well-known brand(s): {brands}. Possible typosquatting.")

    if not recs:
        recs.append("No immediate threats detected. Always stay vigilant online.")

    return recs


# ── MalQR Test Vectors Catalog & Exploit Signatures ───────────────────────────
MALQR_EXACT_PAYLOADS = {
    # SQLi Vectors from MalQR
    "'or'x'='x": {"type": "sqli", "name": "SQL Injection (Auth Bypass)", "desc": "MalQR boolean true exploit 'or'x'='x designed to bypass authentication."},
    "'or'x'='x'-- -": {"type": "sqli", "name": "SQL Injection (Comment Truncation)", "desc": "MalQR SQL injection with SQL comment marker '-- -'."},
    "'or'x'='x'/*": {"type": "sqli", "name": "SQL Injection (Block Comment)", "desc": "MalQR SQL injection with inline C-style comment '/*' truncation."},
    "'or'x'='x'//": {"type": "sqli", "name": "SQL Injection (Slash Comment)", "desc": "MalQR SQL injection with slash-based comment delimiter."},
    "'and'x'='x": {"type": "sqli", "name": "SQL Injection (Boolean AND)", "desc": "MalQR SQL injection testing logic gate 'and' condition."},
    "'and'x'='x'-- -": {"type": "sqli", "name": "SQL Injection (AND + Comment)", "desc": "MalQR SQL injection testing logical AND with comment truncation."},
    "'and'x'='x'/*": {"type": "sqli", "name": "SQL Injection (AND + Comment)", "desc": "MalQR SQL injection testing logical AND with inline comment."},
    "'and'x'='x'//": {"type": "sqli", "name": "SQL Injection (AND + Slash)", "desc": "MalQR SQL injection testing logical AND with slash delimiter."},
    "or 1=1": {"type": "sqli", "name": "SQL Injection (Tautology 1=1)", "desc": "Classic SQL injection tautology payload 'or 1=1'."},
    "or 1=1-- -": {"type": "sqli", "name": "SQL Injection (Tautology + Comment)", "desc": "SQL injection tautology with comment truncation."},
    "or 1=1/*": {"type": "sqli", "name": "SQL Injection (Tautology + Comment)", "desc": "SQL injection tautology with inline comment."},
    "or 1=1//": {"type": "sqli", "name": "SQL Injection (Tautology + Slash)", "desc": "SQL injection tautology with slash comment."},
    "and 1=1": {"type": "sqli", "name": "SQL Injection (Boolean True)", "desc": "SQL injection boolean true probe 'and 1=1'."},
    "and 1=1-- -": {"type": "sqli", "name": "SQL Injection (Boolean True + Comment)", "desc": "SQL injection probe with comment truncation."},
    "and 1=1/*": {"type": "sqli", "name": "SQL Injection (Boolean True + Comment)", "desc": "SQL injection probe with inline comment."},
    "and 1=1//": {"type": "sqli", "name": "SQL Injection (Boolean True + Slash)", "desc": "SQL injection probe with slash comment."},
    "'||'x'='x": {"type": "sqli", "name": "SQL Injection (Concatenation / Logical OR)", "desc": "MalQR SQL injection using Oracle/Postgres '||' concatenation or OR operator."},
    "'||'x'='x'-- -": {"type": "sqli", "name": "SQL Injection (Concatenation + Comment)", "desc": "MalQR SQL injection with concatenation and comment."},
    "'||'x'='x'/*": {"type": "sqli", "name": "SQL Injection (Concatenation + Comment)", "desc": "MalQR SQL injection with concatenation and block comment."},
    "'||'x'='x'//": {"type": "sqli", "name": "SQL Injection (Concatenation + Slash)", "desc": "MalQR SQL injection with concatenation and slash delimiter."},
    "'&&'x'='x": {"type": "sqli", "name": "SQL Injection (Logical AND Operator)", "desc": "MalQR SQL injection using '&&' operator."},
    "'&&'x'='x'-- -": {"type": "sqli", "name": "SQL Injection (AND + Comment)", "desc": "MalQR SQL injection using '&&' with comment."},
    "'&&'x'='x'/*": {"type": "sqli", "name": "SQL Injection (AND + Comment)", "desc": "MalQR SQL injection using '&&' with block comment."},
    "'&&'x'='x'//": {"type": "sqli", "name": "SQL Injection (AND + Slash)", "desc": "MalQR SQL injection using '&&' with slash delimiter."},
    "|| 1=1": {"type": "sqli", "name": "SQL Injection (Pipe Tautology)", "desc": "SQL injection pipe tautology '|| 1=1'."},
    "|| 1=1-- -": {"type": "sqli", "name": "SQL Injection (Pipe Tautology + Comment)", "desc": "SQL injection pipe tautology with comment."},
    "|| 1=1/*": {"type": "sqli", "name": "SQL Injection (Pipe Tautology + Comment)", "desc": "SQL injection pipe tautology with block comment."},
    "|| 1=1//": {"type": "sqli", "name": "SQL Injection (Pipe Tautology + Slash)", "desc": "SQL injection pipe tautology with slash delimiter."},
    "&& 1=1": {"type": "sqli", "name": "SQL Injection (Logical AND Tautology)", "desc": "SQL injection AND operator tautology '&& 1=1'."},
    "&& 1=1-- -": {"type": "sqli", "name": "SQL Injection (Logical AND + Comment)", "desc": "SQL injection AND operator tautology with comment."},
    "&& 1=1/*": {"type": "sqli", "name": "SQL Injection (Logical AND + Comment)", "desc": "SQL injection AND operator tautology with block comment."},
    "&& 1=1//": {"type": "sqli", "name": "SQL Injection (Logical AND + Slash)", "desc": "SQL injection AND operator tautology with slash delimiter."},

    # Command Injection Vectors from MalQR
    "&& echo 'owned' &&": {"type": "ci", "name": "Command Injection (AND Chaining)", "desc": "MalQR OS command injection using '&&' chaining to execute shell payload."},
    "; echo 'owned';": {"type": "ci", "name": "Command Injection (Semicolon Delimiter)", "desc": "MalQR OS command injection using ';' delimiter to execute shell command."},
    "$(echo 'owned')": {"type": "ci", "name": "Command Injection (Subshell Substitution)", "desc": "MalQR OS command injection using '$()' command substitution syntax."},
    "`echo 'owned'`": {"type": "ci", "name": "Command Injection (Backtick Execution)", "desc": "MalQR OS command injection using backtick shell evaluation."},
    "| echo 'owned'": {"type": "ci", "name": "Command Injection (Pipe Execution)", "desc": "MalQR OS command injection using Unix pipe '|' to execute shell command."},

    # XSS Vectors from MalQR
    "<script>alert(1)</script>": {"type": "xss", "name": "Cross-Site Scripting (Script Tag)", "desc": "MalQR stored/reflected XSS payload executing alert(1)."},
    "\"><script>alert(1)</script>": {"type": "xss", "name": "Cross-Site Scripting (Attribute Escape)", "desc": "MalQR XSS escaping HTML attributes with quotes and injecting script tag."},
    "<img/src=c/onerror=alert(1)>": {"type": "xss", "name": "Cross-Site Scripting (Image OnError)", "desc": "MalQR XSS using broken image onerror event handler."},
    "<svg/onload=alert(1)>": {"type": "xss", "name": "Cross-Site Scripting (SVG OnLoad)", "desc": "MalQR XSS using SVG inline onload execution."},

    # Fuzzing / Buffer Overflow Vectors from MalQR
    "\"'`\\": {"type": "fuzz", "name": "Parser Fuzzing (Metacharacters)", "desc": "MalQR scanner fuzzing payload containing quotes, backticks, and escape backslashes."},
    "A*32": {"type": "fuzz", "name": "Buffer Overflow Probe (32 bytes)", "desc": "MalQR buffer overflow / memory corruption test vector."},
    "A*64": {"type": "fuzz", "name": "Buffer Overflow Probe (64 bytes)", "desc": "MalQR buffer overflow / memory corruption test vector."},
    "A*128": {"type": "fuzz", "name": "Buffer Overflow Probe (128 bytes)", "desc": "MalQR buffer overflow / memory corruption test vector."},
    "A*256": {"type": "fuzz", "name": "Buffer Overflow Probe (256 bytes)", "desc": "MalQR buffer overflow / memory corruption test vector."},
    "A*512": {"type": "fuzz", "name": "Buffer Overflow Probe (512 bytes)", "desc": "MalQR buffer overflow / memory corruption test vector."},
    "A*1024": {"type": "fuzz", "name": "Buffer Overflow Probe (1024 bytes)", "desc": "MalQR buffer overflow / memory corruption test vector."},
    "A*2048": {"type": "fuzz", "name": "Buffer Overflow Probe (2048 bytes)", "desc": "MalQR buffer overflow / memory corruption test vector."},
    "A*2953": {"type": "fuzz", "name": "Buffer Overflow Probe (2953 bytes Max)", "desc": "MalQR maximum QR code payload capacity buffer overflow probe."},
}


def detect_malqr_and_exploit_payload(text: str) -> Optional[dict]:
    """Inspect decoded QR/barcode content for MalQR exploits (SQLi, CI, XSS, Buffer Overflow)."""
    if not text:
        return None
    raw = text.strip()

    # 1. Exact catalog match from MalQR
    if raw in MALQR_EXACT_PAYLOADS:
        info = MALQR_EXACT_PAYLOADS[raw]
        return {
            "is_exploit": True,
            "type": info["type"],
            "name": info["name"],
            "description": info["desc"],
            "mitigation": "Enforce strict input parameterization (Prepared Statements / ORM) and context encoding. Never pass unvalidated QR contents to shell or database.",
        }

    raw_lower = raw.lower()

    # 2. SQL Injection Signatures
    sqli_patterns = [
        r"('|\")\s*(or|and)\s*('|\")?\w+('|\")?\s*=",
        r"union\s+select",
        r"\bselect\b.*\bfrom\b",
        r"\binsert\s+into\b",
        r"\bdrop\s+table\b",
        r"\bexec(\s*|\()",
        r"\bwaitfor\s+delay\b",
        r"'\s*or\s*1\s*=\s*1",
        r"\"\s*or\s*1\s*=\s*1",
        r"--\s*-\s*$",
        r"/\*.*\*/",
    ]
    for pat in sqli_patterns:
        if re.search(pat, raw_lower):
            return {
                "is_exploit": True,
                "type": "sqli",
                "name": "SQL Injection Exploit Pattern",
                "description": f"Payload matches SQL injection attack signature targeting database parser: '{raw[:80]}'.",
                "mitigation": "Use parameterized queries or ORM models. Do not concatenate scanner input into SQL strings.",
            }

    # 3. OS Command Injection Signatures
    ci_patterns = [
        r"(;|&&|\|)\s*(cat|ls|rm|echo|whoami|id|nc|bash|sh|curl|wget|ping)\b",
        r"\$\(.*\)",
        r"`.*`",
        r"/etc/passwd",
        r"/bin/sh",
    ]
    for pat in ci_patterns:
        if re.search(pat, raw):
            return {
                "is_exploit": True,
                "type": "ci",
                "name": "OS Command Injection Exploit Pattern",
                "description": f"Payload contains shell command delimiters/execution syntax: '{raw[:80]}'.",
                "mitigation": "Never invoke shell execution functions (e.g. exec, system, subprocess with shell=True) on barcode input.",
            }

    # 4. Cross-Site Scripting (XSS) Signatures
    xss_patterns = [
        r"<script.*?>",
        r"javascript:\s*",
        r"onerror\s*=",
        r"onload\s*=",
        r"onclick\s*=",
        r"alert\s*\(",
        r"<svg.*?/onload",
        r"<img.*?/onerror",
        r"<iframe.*?>",
    ]
    for pat in xss_patterns:
        if re.search(pat, raw_lower):
            return {
                "is_exploit": True,
                "type": "xss",
                "name": "Cross-Site Scripting (XSS) Exploit Pattern",
                "description": f"Payload contains executable script tags or inline DOM event handlers: '{raw[:80]}'.",
                "mitigation": "Sanitize and HTML-encode all decoded content before rendering in the DOM.",
            }

    # 5. Buffer Overflow / Repetition Fuzzing
    if len(raw) >= 32 and (raw.count("A") / len(raw) > 0.8 or raw.count("%s") > 4 or "\x00" in raw):
        return {
            "is_exploit": True,
            "type": "fuzz",
            "name": "Buffer Overflow / Format String Exploit",
            "description": f"Payload contains repeating memory corruption or format string fuzzing tokens (length {len(raw)}).",
            "mitigation": "Enforce strict length bounds and UTF-8 validation on scanned barcode data buffers.",
        }

    return None
