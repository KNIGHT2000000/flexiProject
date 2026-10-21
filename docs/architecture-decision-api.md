# Architecture Decision Record (ADR): AWS Lambda Runtime Strategy

**Status**: ACCEPTED  
**Date**: 2026-10-21  
**Author**: Cloud & Serverless Architecture Team  

---

## 1. Context and Problem Statement
The PhishGuard platform consists of a FastAPI backend providing real-time URL scanning, ML model inference, and threat intelligence correlation. We must evaluate whether the existing application can run cost-effectively and reliably on AWS Lambda or if an ECS/Fargate container architecture is required.

---

## 2. Evaluation of Architectural Options

### Option A: Monolithic Lambda Migration (Mangum ASGI Bridge)
- **Concept**: Wrap the existing FastAPI application with `mangum.Mangum(app)` and execute directly behind AWS API Gateway HTTP API.
- **Feasibility**:
  - **Statelessness**: The core detection engine, ML inference (Scikit-Learn Random Forest), feature extraction, and external threat lookups are completely stateless.
  - **Model Footprint**: The trained Random Forest model (`model.pkl`) is only 244 KB, loading into memory in < 20ms during cold start.
  - **Dependencies**: Total Python dependencies (FastAPI, Scikit-learn, Numpy, Pydantic, SQLAlchemy) easily fit within Lambda container images or standard zipped layers.
- **Limitations**:
  - Headless browser screenshotting (Playwright + Chromium, >300MB) cannot run inside a lightweight zip Lambda.
  - SQLite is single-host ephemeral; multi-instance Lambda requires a managed PostgreSQL instance (Amazon RDS / Aurora Serverless v2).

### Option B: Separate Lambda API Adapter Calling Shared Modules
- **Concept**: Maintain a dedicated Lambda handler that imports shared analysis modules (`app.feature_extractor`, `app.risk_engine`, `app.url_utils`, `app.ssrf_protection`) while retaining the legacy FastAPI routes for on-premise/Docker deployments.
- **Trade-off**: Requires maintaining two separate HTTP dispatchers, increasing maintenance overhead.

### Option C: Containerized ECS / Fargate Service
- **Concept**: Package the entire backend including Chromium/Playwright into a Docker container and run as an ECS Fargate long-running service behind an Application Load Balancer (ALB).
- **Trade-off**: High baseline cost (~$40–$70/month for minimal 24/7 Fargate tasks + ALB) even with zero incoming traffic.

---

## 3. Decision Outcome: Selected Approach (Option A with Gated Browser Isolation)

**We choose Option A (FastAPI adapted for Lambda via Mangum) with gated browser isolation.**

### Key Implementation Decisions:
1. **Unified Codebase with Mangum**:
   - `backend/app/lambda_handler.py` exposes `handler = Mangum(app, lifespan="off")`.
   - `backend/app.py` continues running standard Uvicorn for local development and Docker Compose.
   - Zero duplicated routing logic; 100% contract parity.
2. **Cloud-Native Endpoint (`POST /analyze`)**:
   - Introduces `POST /analyze` with structured request IDs (`X-Request-ID`), telemetry latency measurements, and provider health status.
   - Preserves legacy `POST /api/scan/url` for full backwards compatibility with existing clients and the Chrome extension.
3. **Screenshot Isolation**:
   - Playwright is excluded from synchronous execution in standard Lambda functions. The `include_screenshot` flag defaults to `false`. If full screenshotting is required, it can be decoupled to an asynchronous worker or Fargate task.
4. **Structured Telemetry & Security**:
   - Ingress rate limiting is handled by API Gateway throttling in cloud environments and in-memory fallback locally.
   - Strict SSRF network isolation prevents AWS metadata (`169.254.169.254`) credential leakage.
