from pydantic import BaseModel, EmailStr, Field, ConfigDict
from typing import Optional, Any
from datetime import datetime


# ── Auth ──────────────────────────────────────────────────────────────────────
class UserCreate(BaseModel):
    username: str
    email: str
    password: str


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    email: str
    role: str
    theme: str
    created_at: datetime


class UserUpdate(BaseModel):
    theme: Optional[str] = None
    email: Optional[str] = None


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Optional[str] = None


# ── Scan ──────────────────────────────────────────────────────────────────────
class URLScanRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=2048, description="Target URL string to inspect")


class BulkScanRequest(BaseModel):
    urls: list[str] = Field(..., min_length=1, max_length=50, description="List of target URLs to inspect (max 50)")


class ScanResult(BaseModel):
    url: str
    prediction: str
    risk_score: float
    features: dict
    virustotal: Optional[dict] = None
    google_safe_browsing: Optional[dict] = None
    whois: Optional[dict] = None
    ssl: Optional[dict] = None
    redirect_chain: Optional[list[str]] = None
    typosquatting: Optional[list[dict]] = None
    screenshot: Optional[str] = None   # base64 jpeg
    recommendations: list[str] = []


class BulkScanResult(BaseModel):
    total: int
    results: list[ScanResult]


class ScanHistoryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    url: str
    prediction: str
    risk_score: float
    scanned_at: datetime


class ScanHistoryDetail(ScanHistoryOut):
    features: Optional[str] = None
    virustotal_result: Optional[str] = None
    whois_result: Optional[str] = None
    ssl_result: Optional[str] = None
    redirect_chain: Optional[str] = None
    typosquatting: Optional[str] = None


# ── API Keys ──────────────────────────────────────────────────────────────────
class APIKeyCreate(BaseModel):
    name: str


class APIKeyOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    is_active: bool
    created_at: datetime
    last_used: Optional[datetime] = None


class APIKeyCreated(APIKeyOut):
    raw_key: str   # only returned once at creation


# ── Whitelist ─────────────────────────────────────────────────────────────────
class WhitelistAdd(BaseModel):
    domain: str


class WhitelistOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    domain: str
    added_at: datetime


# ── Email Alerts ──────────────────────────────────────────────────────────────
class EmailAlertSettings(BaseModel):
    enabled: bool = True
    min_risk_score: float = 60.0


class EmailAlertOut(EmailAlertSettings):
    model_config = ConfigDict(from_attributes=True)


# ── Email Header Analyzer ─────────────────────────────────────────────────────
class EmailHeaderRequest(BaseModel):
    headers: str   # raw email header text


class EmailHeaderResult(BaseModel):
    urls_found: int
    results: list[ScanResult]
    email_risk_score: Optional[float] = 0.0
    email_prediction: Optional[str] = "legitimate"
    lures_detected: list[dict] = Field(default_factory=list)
    sender: Optional[dict] = None
    mismatched_links: list[dict] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)


# ── Leaderboard ───────────────────────────────────────────────────────────────
class LeaderboardEntry(BaseModel):
    username: str
    total_scans: int
    phishing_caught: int


# ── Admin ─────────────────────────────────────────────────────────────────────
class AdminUserOut(UserOut):
    is_active: bool
    scan_count: Optional[int] = None


class GlobalStats(BaseModel):
    total_users: int
    total_scans: int
    phishing: int
    suspicious: int
    legitimate: int
