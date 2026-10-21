"""
Strict URL validation, normalization, and safety utilities.
Protects against obfuscation, malformed URLs, homoglyph attacks, and unusual port abuse.
"""
from __future__ import annotations

import re
import socket
import ipaddress
import unicodedata
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode
from typing import Optional
from pydantic import BaseModel
import idna


MAX_URL_LENGTH = 2048
STANDARD_PORTS = {"http": 80, "https": 443}

# Known sensitive query parameters to sanitize before logging or storing in history
SENSITIVE_PARAM_NAMES = {
    "token", "access_token", "auth", "key", "api_key", "apikey",
    "secret", "password", "pass", "pwd", "session", "sessionid",
    "jwt", "sig", "signature", "credential", "code", "refresh_token"
}

# Common Cyrillic and Greek homoglyphs targeting Latin characters
HOMOGLYPH_LOOKALIKES = {
    '\u0430': 'a',  # Cyrillic small letter a
    '\u0441': 'c',  # Cyrillic small letter es
    '\u0435': 'e',  # Cyrillic small letter ie
    '\u0456': 'i',  # Cyrillic small letter byelorussian-ukrainian i
    '\u0458': 'j',  # Cyrillic small letter je
    '\u043e': 'o',  # Cyrillic small letter o
    '\u0440': 'p',  # Cyrillic small letter er
    '\u0455': 's',  # Cyrillic small letter dze
    '\u0445': 'x',  # Cyrillic small letter ha
    '\u0443': 'y',  # Cyrillic small letter u
    '\u03bf': 'o',  # Greek small letter omicron
    '\u03bd': 'v',  # Greek small letter nu
    '\u0410': 'A',  # Cyrillic capital letter A
    '\u0412': 'B',  # Cyrillic capital letter Ve
    '\u0415': 'E',  # Cyrillic capital letter Ie
    '\u041e': 'O',  # Cyrillic capital letter O
    '\u0420': 'P',  # Cyrillic capital letter Er
    '\u0421': 'C',  # Cyrillic capital letter Es
    '\u0422': 'T',  # Cyrillic capital letter Te
    '\u0425': 'X',  # Cyrillic capital letter Ha
}


class URLValidationResult(BaseModel):
    is_valid: bool
    error_message: Optional[str] = None
    original_url: str
    normalized_url: str
    scheme: str = ""
    hostname: str = ""
    ascii_hostname: str = ""
    port: Optional[int] = None
    path: str = ""
    query: str = ""
    fragment: str = ""
    is_ip_address: bool = False
    is_unusual_port: bool = False
    has_homoglyphs: bool = False
    has_punycode: bool = False
    has_at_symbol: bool = False
    is_private_or_reserved_ip: bool = False


def is_ip_hostname(hostname: str) -> tuple[bool, Optional[ipaddress.IPv4Address | ipaddress.IPv6Address]]:
    """Determine if hostname represents an IPv4 or IPv6 address (including bracketed IPv6)."""
    clean_host = hostname.strip("[]").split(":")[0]
    try:
        ip = ipaddress.ip_address(clean_host)
        return True, ip
    except ValueError:
        pass

    # Detect integer, hex, or octal IPv4 notations (e.g. 0x7f000001 or 2130706433)
    if clean_host.isdigit():
        try:
            val = int(clean_host)
            if 0 <= val <= 0xFFFFFFFF:
                return True, ipaddress.IPv4Address(val)
        except (ValueError, OverflowError):
            pass
    elif clean_host.startswith("0x") or clean_host.startswith("0X"):
        try:
            val = int(clean_host, 16)
            if 0 <= val <= 0xFFFFFFFF:
                return True, ipaddress.IPv4Address(val)
        except (ValueError, OverflowError):
            pass

    return False, None


def detect_homoglyphs(text: str) -> tuple[bool, list[str]]:
    """Detect visually confusable characters (homoglyphs) in domain text."""
    confusables_found = []
    has_latin = any('LATIN' in unicodedata.name(c, '') for c in text if c.isalpha())
    for char in text:
        if char in HOMOGLYPH_LOOKALIKES:
            confusables_found.append(f"{char} (confusable with '{HOMOGLYPH_LOOKALIKES[char]}')")
        else:
            char_name = unicodedata.name(char, '')
            if has_latin and any(script in char_name for script in ('CYRILLIC', 'GREEK')):
                confusables_found.append(f"{char} ({char_name})")
    return len(confusables_found) > 0, confusables_found


def validate_and_normalize_url(raw_url: str) -> URLValidationResult:
    """
    Perform strict validation and RFC-compliant normalization on input URLs.
    
    Ensures:
    1. Length is bounded (<= 2048 chars).
    2. Scheme is strictly http or https (defaults to https if scheme omitted).
    3. Hostname is parsed, normalized to lowercase, and converted to Punycode/IDNA if Unicode.
    4. Homoglyphs and confusable characters are detected.
    5. Standard ports are stripped; unusual ports are flagged.
    6. IP addresses (including private/reserved) are identified.
    7. Authority credentials ('@') are flagged.
    """
    if not raw_url or not isinstance(raw_url, str):
        return URLValidationResult(
            is_valid=False,
            error_message="URL must be a non-empty string.",
            original_url=raw_url or "",
            normalized_url="",
        )

    clean_url = raw_url.strip()
    if len(clean_url) > MAX_URL_LENGTH:
        return URLValidationResult(
            is_valid=False,
            error_message=f"URL exceeds maximum allowed length of {MAX_URL_LENGTH} characters.",
            original_url=clean_url,
            normalized_url="",
        )

    # Disallow dangerous schemes like javascript:, data:, file:, vbscript:
    lower_prefix = clean_url.lower()
    for forbidden in ("javascript:", "data:", "file:", "vbscript:", "about:"):
        if lower_prefix.startswith(forbidden):
            return URLValidationResult(
                is_valid=False,
                error_message=f"Forbidden URL scheme: '{forbidden[:-1]}'.",
                original_url=clean_url,
                normalized_url="",
            )

    # Add default scheme if missing
    if not (lower_prefix.startswith("http://") or lower_prefix.startswith("https://")):
        clean_url = "https://" + clean_url

    try:
        parts = urlsplit(clean_url)
    except Exception as e:
        return URLValidationResult(
            is_valid=False,
            error_message=f"Malformed URL structure: {e}",
            original_url=raw_url,
            normalized_url="",
        )

    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        return URLValidationResult(
            is_valid=False,
            error_message=f"Unsupported scheme '{scheme}'. Only http and https are allowed.",
            original_url=raw_url,
            normalized_url="",
        )

    netloc = parts.netloc
    if not netloc:
        return URLValidationResult(
            is_valid=False,
            error_message="URL does not contain a valid host.",
            original_url=raw_url,
            normalized_url="",
        )

    has_at_symbol = "@" in netloc
    # Extract host and port
    try:
        hostname = parts.hostname or ""
    except ValueError as e:
        return URLValidationResult(
            is_valid=False,
            error_message=f"Invalid hostname: {e}",
            original_url=raw_url,
            normalized_url="",
        )

    if not hostname:
        return URLValidationResult(
            is_valid=False,
            error_message="Empty or invalid hostname.",
            original_url=raw_url,
            normalized_url="",
        )

    hostname = hostname.rstrip(".").lower()
    port = parts.port

    # Punycode / IDNA handling
    has_punycode = "xn--" in hostname
    has_homoglyphs, _ = detect_homoglyphs(hostname)
    try:
        ascii_hostname = idna.encode(hostname).decode("ascii")
        if "xn--" in ascii_hostname:
            has_punycode = True
    except Exception:
        ascii_hostname = hostname

    # IP address detection
    is_ip, ip_obj = is_ip_hostname(hostname)
    is_private_or_reserved = False
    if is_ip and ip_obj:
        is_private_or_reserved = (
            ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
            or ip_obj.is_reserved or ip_obj.is_multicast or ip_obj.is_unspecified
        )

    # Port normalization
    is_unusual_port = False
    if port is not None:
        if port == STANDARD_PORTS.get(scheme):
            port = None  # normalize by stripping standard port
        else:
            is_unusual_port = True

    # Reconstruct normalized netloc
    if port is not None:
        normalized_netloc = f"{ascii_hostname}:{port}"
    else:
        normalized_netloc = ascii_hostname

    # Path normalization
    path = parts.path or "/"
    if not path.startswith("/"):
        path = "/" + path

    # Normalized URL assembly
    normalized_url = urlunsplit((scheme, normalized_netloc, path, parts.query, parts.fragment))

    return URLValidationResult(
        is_valid=True,
        original_url=raw_url,
        normalized_url=normalized_url,
        scheme=scheme,
        hostname=hostname,
        ascii_hostname=ascii_hostname,
        port=port,
        path=path,
        query=parts.query,
        fragment=parts.fragment,
        is_ip_address=is_ip,
        is_unusual_port=is_unusual_port,
        has_homoglyphs=has_homoglyphs,
        has_punycode=has_punycode,
        has_at_symbol=has_at_symbol,
        is_private_or_reserved_ip=is_private_or_reserved,
    )


def redact_sensitive_url(url: str) -> str:
    """
    Sanitize sensitive parameters (tokens, credentials, secrets) from URL queries
    prior to persisting to database or writing to logs.
    """
    try:
        parts = urlsplit(url)
        if not parts.query:
            return url

        pairs = parse_qsl(parts.query, keep_blank_values=True)
        sanitized_pairs = []
        for key, val in pairs:
            if key.lower() in SENSITIVE_PARAM_NAMES or any(sub in key.lower() for sub in ("token", "secret", "password")):
                sanitized_pairs.append((key, "[REDACTED]"))
            else:
                sanitized_pairs.append((key, val))

        sanitized_query = urlencode(sanitized_pairs)
        return urlunsplit((parts.scheme, parts.netloc, parts.path, sanitized_query, parts.fragment))
    except Exception:
        return url
