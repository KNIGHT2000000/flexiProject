import os
import uuid
import json
import logging
from time import time
from collections import defaultdict
from datetime import datetime, timezone
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.database import engine, Base
from app.routers import auth, scan, apikeys, whitelist, alerts, admin, users, analyze, threat

# Ensure database tables exist
Base.metadata.create_all(bind=engine)

# Structured logger setup
logger = logging.getLogger("phishguard.api")
logging.basicConfig(level=logging.INFO, format="%(message)s")

app = FastAPI(
    title="PhishGuard Cloud — AI Phishing Detection & Threat Intelligence Platform",
    description="Enterprise-grade cloud platform for phishing link detection, QR inspection, and threat intelligence correlation.",
    version="2.1.0",
)

# ── CORS Configuration ────────────────────────────────────────────────────────
cors_env = os.getenv("CORS_ORIGINS", "")
allowed_origins = [o.strip() for o in cors_env.split(",") if o.strip()]
if not allowed_origins:
    allowed_origins = [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173",
    ]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_origin_regex=r"^chrome-extension://.*$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-Request-ID"],
)

# ── Rate Limiter State ────────────────────────────────────────────────────────
_rate_store: dict[str, list[float]] = defaultdict(list)
RATE_LIMIT = int(os.getenv("RATE_LIMIT", "30"))          # requests
RATE_WINDOW = int(os.getenv("RATE_WINDOW", "60"))        # seconds


# ── Middleware: Request ID, Telemetry & Structured Logging ───────────────────
@app.middleware("http")
async def telemetry_and_logging(request: Request, call_next):
    req_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    request.state.request_id = req_id

    # In-memory rate limiting fallback for local dev / single instance
    if request.url.path.startswith("/api/scan") or request.url.path.startswith("/analyze"):
        client_ip = request.client.host if request.client else "unknown"
        now = time()
        window_start = now - RATE_WINDOW
        _rate_store[client_ip] = [t for t in _rate_store[client_ip] if t > window_start]
        if len(_rate_store[client_ip]) >= RATE_LIMIT:
            return JSONResponse(
                status_code=429,
                content={
                    "detail": f"Rate limit exceeded: {RATE_LIMIT} requests per {RATE_WINDOW}s",
                    "request_id": req_id,
                },
                headers={"X-Request-ID": req_id},
            )
        _rate_store[client_ip].append(now)

    start_time = time()
    try:
        response = await call_next(request)
    except Exception as exc:
        duration_ms = round((time() - start_time) * 1000, 2)
        logger.error(json.dumps({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "request_id": req_id,
            "method": request.method,
            "path": request.url.path,
            "error": str(exc),
            "duration_ms": duration_ms,
        }))
        return JSONResponse(
            status_code=500,
            content={
                "detail": "Internal server error occurred.",
                "request_id": req_id,
                "status_code": 500,
            },
            headers={"X-Request-ID": req_id},
        )

    duration_ms = round((time() - start_time) * 1000, 2)
    response.headers["X-Request-ID"] = req_id

    # Structured CloudWatch-compatible access log
    logger.info(json.dumps({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "request_id": req_id,
        "method": request.method,
        "path": request.url.path,
        "status_code": response.status_code,
        "duration_ms": duration_ms,
    }))
    return response


# ── Standardized Exception Handlers ───────────────────────────────────────────
@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    req_id = getattr(request.state, "request_id", "req-unknown")
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "detail": exc.detail,
            "status_code": exc.status_code,
            "request_id": req_id,
            "path": request.url.path,
        },
        headers={"X-Request-ID": req_id},
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    req_id = getattr(request.state, "request_id", "req-unknown")
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "detail": exc.errors(),
            "status_code": 422,
            "request_id": req_id,
            "path": request.url.path,
        },
        headers={"X-Request-ID": req_id},
    )


# ── Routers ───────────────────────────────────────────────────────────────────
app.include_router(analyze.router)
app.include_router(auth.router)
app.include_router(scan.router)
app.include_router(apikeys.router)
app.include_router(whitelist.router)
app.include_router(alerts.router)
app.include_router(admin.router)
app.include_router(users.router)
app.include_router(threat.router)


@app.get("/")
def root(request: Request):
    req_id = getattr(request.state, "request_id", None)
    return {
        "message": "PhishGuard AI Cloud API v2.1 is running",
        "docs": "/docs",
        "request_id": req_id,
    }


@app.get("/health")
def health():
    return {
        "status": "ok",
        "version": "2.1.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
