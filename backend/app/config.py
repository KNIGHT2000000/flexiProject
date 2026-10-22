from pydantic_settings import BaseSettings, SettingsConfigDict
from functools import lru_cache
from typing import Optional


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "sqlite:///./phishing.db"
    secret_key: str = "changeme-super-secret-key"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    virustotal_api_key: str = ""
    google_safe_browsing_api_key: str = ""

    # SMTP for email alerts (optional)
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = "phishguard@example.com"
    smtp_tls: bool = True


@lru_cache
def get_settings() -> Settings:
    return Settings()

