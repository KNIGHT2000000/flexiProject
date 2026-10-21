# PhishGuard Cloud: Implementation Roadmap & Engineering Plan

## 1. Guiding Principles & Non-Negotiables
1. **Preserve Working Functionality**: Keep all existing core features (ML detection, heuristic fallback, QR scanning, JWT auth, scan history, user whitelist, email alerts, Chrome extension).
2. **Zero Greenfield Rewrites**: Enhance the existing FastAPI backend and React frontend incrementally.
3. **No Credential Exposure**: Never hardcode secrets, commit API keys, or expose server credentials in frontend code or Git.
4. **SSRF Hardening**: Prohibit unisolated, unvalidated outbound HTTP requests to user-submitted URLs.
5. **Cost-Conscious Serverless**: Introduce AWS resources with justifiable cost models; avoid unnecessary operational overhead (e.g. unneeded Redis clusters).

---

## 2. Phase-by-Phase Execution Plan

### Phase 0: Repository Audit and Baseline (Mandatory Baseline)
- **Status**: IN PROGRESS
- **Deliverables**:
  - `docs/architecture-current.md`: Detailed structural model of existing frontend, backend, ML, threat intel, and extension.
  - `docs/baseline-report.md`: Record of initial test results, working vs. broken components, startup and inference metrics.
  - `docs/api-contracts.md`: Specification of existing routes and schemas.
  - `docs/threat-model.md`: STRIDE analysis and discovery of SSRF risks.
  - `docs/implementation-roadmap.md`: Architectural decisions and migration blueprint.
- **Exit Criteria**: Baseline audit completed, known errors cataloged, user approval obtained before code modification.

---

### Phase 1: Application Hardening & SSRF Defense
- **Objectives**:
  - Implement strict URL validation and normalization (RFC 3986 compliant, Punycode/IDNA handling, Unicode homoglyph detection).
  - Secure the scan path: remove unvalidated synchronous HTTP `trace_redirects` and Playwright browser calls from the default pipeline to prevent SSRF against AWS metadata (`169.254.169.254`) and internal subnets.
  - Fix model path discovery mismatch between `scripts/train_model.py` and `app/routers/scan.py`.
  - Fix missing icon directory references in the Chrome extension manifest.
  - Add comprehensive unit and regression tests for URL normalization and feature extraction.
- **Exit Criteria**: All pre-existing test suites pass; new unit and regression tests pass; SSRF vectors neutralized.

---

### Phase 2: Resilient Threat-Intelligence Architecture
- **Objectives**:
  - Refactor monolithic functions in `app/threat_intel.py` into decoupled Provider Adapters:
    - `VirusTotalAdapter`: Bounded timeouts, quota error handling, and structured telemetry.
    - `GoogleThreatIntelligenceAdapter`: Integration with Google Safe Browsing / Web Risk API with API key protection.
    - `RDAPAdapter`: Structured registration age calculation with fallback for redacted WHOIS data.
  - Define unified provider response model (`status`, `match_category`, `latency_ms`, `error_class`).
  - Introduce an aggregation layer that synthesizes ML, heuristics, and threat providers into versioned risk scores without double-counting.
- **Exit Criteria**: Unit tests with mocked provider responses (positive, negative, rate-limited, timeout) verifying safe failure modes without breaking scan requests.

---

### Phase 3: AWS-Compatible API Layer & Contracts
- **Objectives**:
  - Architectural evaluation of runtime: evaluate AWS Lambda (`Mangum` ASGI adapter) vs. containerized ECS/Fargate based on dependency size (PyTorch/Playwright vs. lightweight scikit-learn).
  - Introduce backward-compatible `/analyze` endpoint while preserving legacy `/api/scan/url`.
  - Standardize error responses (RFC 7807 problem details) with unique `request_id` correlation.
  - Generate OpenAPI 3.1 specification and automated API contract comparison tests.
- **Exit Criteria**: Contract tests pass; existing frontend and Chrome extension communicate seamlessly with the updated API.

---

### Phase 4: AWS Serverless Infrastructure (SAM / CloudFormation)
- **Objectives**:
  - Author AWS SAM `template.yaml`:
    - API Gateway HTTP API with CORS configuration.
    - AWS Lambda function for FastAPI backend with least-privilege IAM execution roles.
    - AWS Secrets Manager integration for JWT secrets and Threat Intel API keys.
    - S3 private bucket with CloudFront distribution (OAC) for hosting static React assets.
    - CloudWatch Log Group with 14-day retention.
  - Provide environment configurations (`samconfig.toml` for staging and production).
  - Document deployment commands and teardown scripts.
- **Exit Criteria**: Validated SAM template; successful deployment verification in AWS sandbox; cost driver analysis documented.

---

### Phase 5: Security & Abuse Resistance
- **Objectives**:
  - Enforce API Gateway throttling and usage plans.
  - Strict input size validation (max URL length 2048 chars, max QR file size 5MB).
  - Redact sensitive parameters (`token`, `password`, `key`) from URLs prior to database logging.
  - Complete security assessment report documenting mitigations for all STRIDE items.
- **Exit Criteria**: Security audit report finalized; zero critical/high automated security scanner findings.

---

### Phase 6: Observability, Metrics & Performance
- **Objectives**:
  - Implement structured JSON logging (CloudWatch compatible) with request latency, ML inference duration, and provider response times.
  - Establish CloudWatch metrics and alarms (5xx error rate > 2%, Lambda throttling, provider timeouts).
  - Conduct bounded load testing (p50, p95, p99 latency reporting) without overloading third-party APIs.
- **Exit Criteria**: Documented baseline vs. warm performance metrics and functional CloudWatch dashboard configurations.

---

### Phase 7: Automated CI/CD Pipeline
- **Objectives**:
  - Enhance GitHub Actions workflows with pull-request checks (linting, test matrix, secret scanning via Trivy/GitGuardian, SAM validate).
  - Configure secure AWS deployment using GitHub OIDC role assumption (no permanent AWS access keys).
  - Automated staging smoke tests.
- **Exit Criteria**: Clean checkout executes all quality gates; CI/CD pipeline validated end-to-end.

---

### Phase 8: Acceptance Testing & Model Evaluation
- **Objectives**:
  - Evaluate Random Forest classifier on labeled dataset: calculate precision, recall, F1-score, and confusion matrix.
  - End-to-end smoke tests: guest scans, authenticated scans, bulk scans, QR code scans, whitelist bypasses, and Chrome extension integration.
- **Exit Criteria**: All acceptance criteria satisfied; ML evaluation metrics verified.

---

### Phase 9: Final Documentation & Demonstration Runbook
- **Objectives**:
  - Overhaul `README.md` with updated architecture diagrams, AWS deployment guide, environment variables reference, and local dev instructions.
  - Provide live demonstration script covering benign, suspicious, and provider-error test cases.
- **Exit Criteria**: Final sign-off and repository handoff.
