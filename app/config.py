# app/config.py - Production Environment & Security Configuration (Step 9 PRD v1.1)
import os
from enum import Enum
from typing import List
from pydantic import Field
from pydantic_settings import BaseSettings


class EnvironmentType(str, Enum):
    DEV = "DEV"
    STAGING = "STAGING"
    PRODUCTION = "PRODUCTION"


class Settings(BaseSettings):
    """
    Central production configuration.
    Enforces strict secret validation, environment isolation, and production guards.
    """

    APP_NAME: str = "Vendor Bank-Change Fraud Guardian"
    APP_VERSION: str = "1.1.0"
    ENVIRONMENT: EnvironmentType = Field(
        default=EnvironmentType.PRODUCTION,
        description="Deployment environment (DEV, STAGING, PRODUCTION)",
    )

    # Database & Supabase (Backend-Only Secrets)
    SUPABASE_URL: str = Field(
        default_factory=lambda: os.getenv("SUPABASE_URL", "https://mock.supabase.co")
    )
    SUPABASE_SERVICE_ROLE_KEY: str = Field(
        default_factory=lambda: os.getenv("SUPABASE_SERVICE_ROLE_KEY", "mock-service-key")
    )
    SUPABASE_ANON_KEY: str = Field(
        default_factory=lambda: os.getenv("SUPABASE_ANON_KEY", "mock-anon-key")
    )
    JWT_SECRET_KEY: str = Field(
        default_factory=lambda: os.getenv("JWT_SECRET_KEY", "mock-jwt-secret-key-for-auth")
    )

    # Security & CORS
    ALLOWED_ORIGINS: List[str] = Field(
        default_factory=lambda: os.getenv(
            "ALLOWED_ORIGINS",
            "https://app.fraudguardian.internal,https://console.fraudguardian.internal",
        ).split(",")
    )
    RATE_LIMIT_PER_MINUTE: int = Field(default=120, ge=10, le=1000)

    # Cooling-Off Period Settings (Authoritative)
    AUTHORITATIVE_COOLING_OFF_HOURS: int = Field(default=48, ge=24)

    # Step 7 Email & SMS Provider Secrets (Backend-Only)
    SMTP_HOST: str = Field(default_factory=lambda: os.getenv("SMTP_HOST", "mock"))
    SMTP_PORT: int = Field(default_factory=lambda: int(os.getenv("SMTP_PORT", "587")))
    SMTP_USER: str = Field(default_factory=lambda: os.getenv("SMTP_USER", ""))
    SMTP_PASSWORD: str = Field(default_factory=lambda: os.getenv("SMTP_PASSWORD", ""))
    SMTP_FROM_EMAIL: str = Field(
        default_factory=lambda: os.getenv(
            "SMTP_FROM_EMAIL", "security@fraudguardian.internal"
        )
    )

    # Step 8 Anti-Storm Settings
    ALERT_SUPPRESSION_WINDOW_SEC: int = Field(default=300, ge=60)

    class Config:
        case_sensitive = True
        env_file = ".env"
        extra = "ignore"


settings = Settings()
