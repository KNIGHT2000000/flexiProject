# Threat Model: PhishGuard Platform (STRIDE & Architectural Security Audit)

## 1. Executive Summary

This document details the threat model for the existing PhishGuard Phishing Link Detection platform prior to cloud hardening. The audit focuses on identifying vulnerabilities across data in transit, data at rest, external integrations, machine learning ingestion, and network egress boundaries.

---

## 2. Threat Classification (STRIDE)

| Threat Category | Existing Risk / Finding | Severity | Existing Mitigation | Residual Risk |
|---|---|---|---|---|
| **Spoofing** | JWT uses symmetric HS256 with default fallback secret `"changeme-super-secret-key"`. In Docker, default secret is `"change-this-in-production"`. | **HIGH** | Configurable via `.env` | If deployed without `.env`, attackers can forge admin JWT tokens. |
| **Tampering** | User whitelist short-circuits verdicts directly: any user can whitelist a domain and receive a 0.0 risk score. | **MEDIUM** | Filtered by `user_id` | Malicious user cannot alter other users' scans, but admin cannot audit whitelist bypasses. |
| **Repudiation** | Scan history logs URLs and user IDs, but does not capture IP addresses, User-Agents, or cryptographic signatures for audit logs. | **LOW** | Timestamps recorded in SQLite/Postgres | Incomplete audit trail for administrative actions (e.g., banning domains, user toggling). |
| **Information Disclosure** | **CRITICAL: SSRF via Redirect Tracing & Screenshots**. Outbound requests to `169.254.169.254` (AWS IMDS), loopback (`127.0.0.1`), or private subnets can leak cloud metadata/credentials. | **CRITICAL** | None currently implemented in `threat_intel.py`. | Cloud deployment exposes IAM role credentials via AWS IMDSv1/v2 if SSRF is unmitigated. |
| **Denial of Service** | In-memory rate limiting (`30 req/60s`) does not survive restarts, does not share state across workers, and is bypassed in distributed/serverless setups. Bulk scans allow 50 URLs with 5 network calls each. | **HIGH** | FastAPI middleware | CPU/socket exhaustion on backend via bulk scans and concurrent Playwright screenshots. |
| **Elevation of Privilege** | User role toggle endpoint (`PATCH /api/admin/users/{user_id}/role`) restricted by `_require_admin`, but initial admin bootstrapping is undefined (all registered users default to `role="user"`). | **MEDIUM** | Role check in route dependency | Manual database tampering required to seed the first admin; risks privilege escalation if admin check has logic flaws. |

---

## 3. High-Priority Vulnerability Findings

### Finding 1: Unrestricted Outbound Network Egress (SSRF via Redirect Tracer & Screenshotter)
- **Vulnerable Locations**:
  - `backend/app/routers/scan.py:106`: `redirect_chain = await trace_redirects(url)` is invoked unconditionally on **every** scanned URL.
  - `backend/app/threat_intel.py:126-147`: `trace_redirects()` uses `httpx.AsyncClient(follow_redirects=True, timeout=10, max_redirects=10)`.
  - `backend/app/threat_intel.py:167-181`: `capture_screenshot()` launches Playwright headless Chromium and executes `page.goto(url, timeout=15000)`.
- **Exploitation Vector**:
  An attacker submits:
  ```json
  POST /api/scan/url
  {"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}
  ```
  Or a malicious redirect chain:
  `http://evil.com/redirect -> http://127.0.0.1:5432/`
- **Impact**: Server-Side Request Forgery (SSRF), internal VPC network scanning, local service fingerprinting, and AWS credential exfiltration.
- **Remediation Plan (Phase 1 & Phase 5)**:
  1. Disable automatic outbound URL navigation in standard scan path.
  2. Implement strict URL parsing, IPv4/IPv6 literal normalization, and CIDR blocking for:
     - Loopback (`127.0.0.0/8`, `::1`)
     - Private networks (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`)
     - Link-local and cloud metadata (`169.254.169.254`, `fe80::/10`)
     - Broadcast and multicast ranges
  3. Validate DNS resolution at each redirect hop before issuing an HTTP connection to prevent DNS rebinding.

### Finding 2: Unbounded Input & File Upload Processing (QR Code DoS)
- **Vulnerable Location**: `backend/app/routers/scan.py:210-230`:
  `file: UploadFile = File(...)` is read completely into memory: `contents = await file.read()`, then passed to `Image.open(io.BytesIO(contents))`.
- **Impact**: Memory exhaustion (Decompression Bomb / Zip-bomb style image exploits) and DoS through multi-gigabyte payload uploads.
- **Remediation Plan**:
  1. Add strict payload size limits (e.g., maximum 5MB for QR image uploads).
  2. Validate image dimensions and MIME types before decoding.

### Finding 3: In-Memory Rate Limiting Incompatible with Multi-Worker / Serverless
- **Vulnerable Location**: `backend/app/main.py:26-44`:
  `_rate_store: dict[str, list[float]] = defaultdict(list)`
- **Impact**:
  - In a multi-worker ASGI setup (e.g. Uvicorn with `--workers 4`), rate limits are split across workers and not shared.
  - In AWS Lambda, every cold start or concurrent container creates an isolated in-memory dictionary, completely nullifying rate protection.
- **Remediation Plan**:
  - Offload rate limiting to API Gateway throttling / AWS WAF at the cloud ingress layer, while preserving local fallback for local development.

### Finding 4: Sensitive URL Logging and URL Privacy
- **Vulnerable Location**: `backend/app/routers/scan.py:114-127`:
  Full submitted URLs are persisted in `ScanHistory` without user consent toggles or redaction.
- **Impact**: Sensitive tokens embedded in query strings (e.g. `https://reset.service.com/token=xyz`) are stored in plain text and exposed on `/api/scan/feed` if flagged as suspicious.
- **Remediation Plan**:
  1. Strip or redact sensitive query parameters (token, session, key, auth, password) before persisting to public feeds or logs.
  2. Never expose private scan histories in the public `/api/scan/feed`.

---

## 4. Threat Matrix & Trust Boundaries

```
[Untrusted Client / Chrome Extension]
       |  (1) HTTPS / JSON payload (URL or QR file)
[Ingress Boundary: API Gateway / Reverse Proxy]
       |  (2) Authenticated / Authorized Request
[Application Core: FastAPI / Lambda Handler]
       |
       +---> [Internal DB: Postgres / SQLite] (SQLAlchemy ORM, parameterized)
       |
       |  (3) Untrusted Network Egress Boundary (Strict Egress Control Required)
       +---> [Threat Intel Providers: VirusTotal / Safe Browsing / RDAP]
       |
       X-.-! [BANNED]: Arbitrary User URL HTTP Fetching without Network Isolation
```
