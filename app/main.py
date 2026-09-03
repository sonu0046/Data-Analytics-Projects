# app/main.py - Production FastAPI Application Entry Point (Step 10 PRD v1.1 Compliant)
import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

# Configuration & Middleware
from app.config import settings
from app.middleware.security_headers import ProductionSecurityHeadersMiddleware

# Routers
from app.routers.risk_engine import router as risk_engine_router
from app.routers.ingestion import router as ingestion_router
from app.routers.maker_verification import router as maker_router
from app.routers.checker_approval import router as checker_router
from app.routers.notifications import router as notifications_router
from app.routers.monitoring import router as monitoring_router
from app.routers.billing import router as billing_router

app = FastAPI(
    title=settings.APP_NAME,
    description="Multi-tenant, AI-assisted & Deterministic Fraud Prevention System with Maker-Checker Separation & SaaS Billing",
    version=settings.APP_VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
)

# 1. Production Security Headers Middleware
app.add_middleware(ProductionSecurityHeadersMiddleware)

# 2. CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Company-ID"],
)

# 3. Include API Routers
app.include_router(risk_engine_router)
app.include_router(ingestion_router)
app.include_router(maker_router)
app.include_router(checker_router)
app.include_router(notifications_router)
app.include_router(monitoring_router)
app.include_router(billing_router)


# 4. Production Health Check
@app.get("/health", tags=["System"])
async def health_check():
    return {
        "status": "healthy",
        "service": "vendor-fraud-guardian",
        "version": settings.APP_VERSION,
        "environment": settings.ENVIRONMENT.value,
        "prd_version": "v1.1",
        "security_controls": "LOCKED_AND_HARDENED",
        "saas_billing": "ACTIVE_AND_ENFORCED",
        "architecture": "4-Brothers-Multi-Tenant",
    }


# 5. Serve Frontend Static Files
frontend_dir = os.path.join(os.path.dirname(__file__), "..", "frontend")
if os.path.exists(frontend_dir):
    app.mount(
        "/static",
        StaticFiles(directory=frontend_dir),
        name="static",
    )


@app.get("/{full_path:path}", include_in_schema=False)
async def serve_spa(full_path: str):
    """Serve Single Page Application (SPA) frontend."""
    index_file = os.path.join(
        os.path.dirname(__file__), "..", "frontend", "index.html"
    )
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return {
        "message": "Vendor Fraud Guardian Production API is active. Frontend build ready."
    }
