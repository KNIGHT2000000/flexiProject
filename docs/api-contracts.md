# API Contracts Reference Specification (Baseline)

## Overview
All endpoints accept and return JSON unless otherwise stated. Authentication is handled via HTTP Bearer token headers:
`Authorization: Bearer <jwt_access_token>`.

Base URL (Local): `http://localhost:8000`
OpenAPI Documentation: `http://localhost:8000/docs`

---

## 1. System Endpoints

### 1.1 Root
- **Method**: `GET /`
- **Auth**: None
- **Response `200 OK`**:
  ```json
  {
    "message": "PhishGuard AI API v2 is running",
    "docs": "/docs"
  }
  ```

### 1.2 Health Check
- **Method**: `GET /health`
- **Auth**: None
- **Response `200 OK`**:
  ```json
  {
    "status": "ok",
    "version": "2.0.0"
  }
  ```

---

## 2. Authentication (`/api/auth`)

### 2.1 Register
- **Method**: `POST /api/auth/register`
- **Auth**: None
- **Request Body**:
  ```json
  {
    "username": "alice",
    "email": "alice@example.com",
    "password": "SecurePassword123!"
  }
  ```
- **Response `200 OK`**:
  ```json
  {
    "id": 1,
    "username": "alice",
    "email": "alice@example.com",
    "role": "user",
    "theme": "dark",
    "created_at": "2026-10-21T06:00:00Z"
  }
  ```
- **Error Responses**: `400 Bad Request` ("Username or email already registered")

### 2.2 Login
- **Method**: `POST /api/auth/login`
- **Auth**: None
- **Content-Type**: `application/x-www-form-urlencoded`
- **Request Body**: `username=alice&password=SecurePassword123!`
- **Response `200 OK`**:
  ```json
  {
    "access_token": "eyJhbGciOiJIUzI1NiIsIn...",
    "token_type": "bearer"
  }
  ```
- **Error Responses**: `401 Unauthorized` ("Invalid credentials")

### 2.3 Current User Info
- **Method**: `GET /api/auth/me`
- **Auth**: Bearer Token
- **Response `200 OK`**: Returns `UserOut` object.

---

## 3. URL & Threat Scanning (`/api/scan`)

### 3.1 Scan Single URL
- **Method**: `POST /api/scan/url`
- **Query Params**: `screenshot` (bool, optional, default `false`)
- **Auth**: Optional (attaches scan to user if token provided)
- **Request Body**:
  ```json
  {
    "url": "https://example.com"
  }
  ```
- **Response `200 OK`**:
  ```json
  {
    "url": "https://example.com",
    "prediction": "legitimate",
    "risk_score": 0.0,
    "features": {
      "url_length": 19,
      "domain_length": 11,
      "path_length": 0,
      "num_dots": 1,
      "num_hyphens": 0,
      "num_underscores": 0,
      "num_slashes": 0,
      "num_question_marks": 0,
      "num_equals": 0,
      "num_ampersands": 0,
      "num_at": 0,
      "num_exclamation": 0,
      "num_percent": 0,
      "num_digits_in_url": 0,
      "has_ip_address": 0,
      "has_at_symbol": 0,
      "has_double_slash_redirect": 0,
      "uses_https": 1,
      "num_subdomains": 0,
      "has_hyphen_in_domain": 0,
      "domain_has_digits": 0,
      "has_suspicious_keywords": 0,
      "subdomain_suspicious": 0,
      "has_suspicious_tld": 0,
      "has_hex_encoding": 0,
      "has_punycode": 0,
      "has_non_standard_port": 0,
      "url_depth": 0
    },
    "virustotal": {
      "available": false,
      "error": "VirusTotal API key not configured"
    },
    "whois": {
      "domain": "example.com",
      "registrar": "RESERVED-Internet Assigned Numbers Authority",
      "creation_date": "1995-08-14T04:00:00",
      "expiry_date": "2027-08-13T04:00:00",
      "domain_age_days": 11391,
      "is_new_domain": false,
      "country": null,
      "org": null
    },
    "ssl": {
      "has_ssl": true,
      "issuer": "DigiCert Global Root G2",
      "subject": "www.example.org",
      "valid_from": "2026-01-15T00:00:00",
      "valid_until": "2027-02-15T23:59:59",
      "days_remaining": 117,
      "is_expired": false,
      "is_expiring_soon": false
    },
    "redirect_chain": [
      "https://example.com"
    ],
    "typosquatting": [],
    "screenshot": null,
    "recommendations": [
      "No immediate threats detected. Always stay vigilant online."
    ]
  }
  ```

### 3.2 Bulk Scan
- **Method**: `POST /api/scan/bulk`
- **Auth**: Optional
- **Request Body**:
  ```json
  {
    "urls": [
      "https://google.com",
      "http://phish-secure-login.tk/verify"
    ]
  }
  ```
- **Limits**: Maximum 50 URLs per request.
- **Response `200 OK`**:
  ```json
  {
    "total": 2,
    "results": [ /* array of ScanResult */ ]
  }
  ```

### 3.3 QR Code Scan
- **Method**: `POST /api/scan/qr`
- **Auth**: Optional
- **Content-Type**: `multipart/form-data`
- **Request Body**: `file`: Binary image file (PNG/JPG)
- **Response `200 OK`**: Returns `ScanResult` for decoded URL.
- **Error Responses**: `400 Bad Request` ("No QR code detected in image"), `503 Service Unavailable` ("QR scanning unavailable")

### 3.4 Scan History
- **Method**: `GET /api/scan/history`
- **Query Params**: `limit` (int, default 50, max 500), `offset` (int, default 0), `prediction` (string), `min_risk` (float), `max_risk` (float), `search` (string)
- **Response `200 OK`**: Array of `ScanHistoryOut`:
  ```json
  [
    {
      "id": 1,
      "url": "https://example.com",
      "prediction": "legitimate",
      "risk_score": 0.0,
      "scanned_at": "2026-10-21T06:05:00Z"
    }
  ]
  ```

### 3.5 Export History
- **Method**: `GET /api/scan/history/export?fmt={csv|json}`
- **Auth**: Required
- **Response `200 OK`**: Streaming file download (`scan_history.csv` or `scan_history.json`).

### 3.6 Scan Statistics
- **Method**: `GET /api/scan/stats`
- **Auth**: Optional (filters to user if authenticated; global if guest)
- **Response `200 OK`**:
  ```json
  {
    "total": 120,
    "phishing": 45,
    "suspicious": 15,
    "legitimate": 60
  }
  ```

### 3.7 Public Threat Feed
- **Method**: `GET /api/scan/feed?limit=20`
- **Auth**: None
- **Response `200 OK`**: Array of latest phishing/suspicious URLs.

### 3.8 Community Leaderboard
- **Method**: `GET /api/scan/leaderboard?limit=10`
- **Auth**: None
- **Response `200 OK`**:
  ```json
  [
    {
      "username": "hunter_bob",
      "total_scans": 412,
      "phishing_caught": 87
    }
  ]
  ```

### 3.9 Email Headers Analysis
- **Method**: `POST /api/scan/email-headers`
- **Auth**: Optional
- **Request Body**: `{"headers": "Received: from ... Message-ID: ... https://..."}`
- **Response `200 OK`**:
  ```json
  {
    "urls_found": 1,
    "results": [ /* array of ScanResult */ ]
  }
  ```

---

## 4. Management & Administrative Endpoints

### 4.1 API Keys (`/api/apikeys`)
- `GET /api/apikeys`: List keys for active user.
- `POST /api/apikeys`: Create key `{"name": "cli-app"}` -> Returns `raw_key: "pg_..."`. Max 5 active keys.
- `DELETE /api/apikeys/{key_id}`: Revokes key.

### 4.2 Whitelist (`/api/whitelist`)
- `GET /api/whitelist`: User's domain whitelist.
- `POST /api/whitelist`: Add domain `{"domain": "trusted-portal.com"}`.
- `DELETE /api/whitelist/{entry_id}`: Delete whitelisted domain.

### 4.3 Email Alerts (`/api/alerts`)
- `GET /api/alerts`: Retrieve email alert preference.
- `PUT /api/alerts`: `{"enabled": true, "min_risk_score": 60.0}`.

### 4.4 Admin Panel (`/api/admin`)
- `GET /api/admin/stats`: Global system statistics.
- `GET /api/admin/users`: User directory with scan counts.
- `PATCH /api/admin/users/{user_id}/toggle`: Activate/deactivate user.
- `PATCH /api/admin/users/{user_id}/role`: Set user role (`user` or `admin`).
- `GET /api/admin/scans`: All user scans.
- `GET /api/admin/banned`: Global domain blacklist.
- `POST /api/admin/banned?domain=...&reason=...`: Ban domain globally.
- `DELETE /api/admin/banned/{domain_id}`: Unban domain.
