"""
CloudGuard — FastAPI Application Entry Point

Architecture:
  Telemetry → /api/events (POST) → Detection Pipeline → Incidents → Dashboard
"""
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import logging

from app.core.config import settings
from app.core.body_limit import BodyLimitMiddleware
from app.core.auth import get_principal, require_roles
from app.core.database import init_db
from app.api.health import router as health_router
from app.api.events import router as events_router
from app.api.containers import router as containers_router
from app.api.incidents import router as incidents_router
from app.api.analytics import router as analytics_router
from app.api.demo import router as demo_router
from app.api.model import router as model_router
from app.api.sensors import router as sensors_router
from app.api.audit import router as audit_router
from app.detection.anomaly import load_model

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("cloudguard")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifecycle: startup and shutdown."""
    logger.info("CloudGuard starting up...")
    logger.info(f"Environment: {settings.APP_ENV}")
    configured_keys = [key for key in (
        settings.SENSOR_API_KEY, settings.VIEWER_API_KEY,
        settings.ANALYST_API_KEY, settings.ADMIN_API_KEY,
    ) if key]
    if settings.APP_ENV == "production":
        if (
            not settings.SENSOR_API_KEY or not settings.ADMIN_API_KEY
            or any(len(key) < 32 for key in configured_keys)
            or len(configured_keys) != len(set(configured_keys))
            or len(settings.SECRET_KEY) < 32
            or "change-me" in settings.SECRET_KEY.lower()
        ):
            raise RuntimeError("Production requires unique 32+ character sensor/admin keys and SECRET_KEY")
    elif not configured_keys and not settings.API_KEY:
        raise RuntimeError("Configure a scoped API key or development API_KEY")
    logger.info(f"Demo mode: {settings.DEMO_MODE_ENABLED}")

    # Initialize database tables
    await init_db()
    load_model()
    logger.info("Database initialized ✓")

    yield

    logger.info("CloudGuard shutting down...")


# ─── FastAPI Application ──────────────────────────────────────────────────────

app = FastAPI(
    title="CloudGuard API",
    description=(
        "Container alert triage using Falco alerts or labeled demo events, "
        "rule detection, optional trained anomaly scoring, and incident management."
    ),
    version=settings.APP_VERSION,
    docs_url=None if settings.APP_ENV == "production" else "/api/docs",
    redoc_url=None if settings.APP_ENV == "production" else "/api/redoc",
    openapi_url=None if settings.APP_ENV == "production" else "/api/openapi.json",
    lifespan=lifespan,
)
app.add_middleware(BodyLimitMiddleware)

# ─── CORS ────────────────────────────────────────────────────────────────────
if settings.APP_ENV != "production":
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[settings.FRONTEND_URL, "http://localhost:3000", "http://127.0.0.1:3000"],
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["*"],
    )

# ─── Global Exception Handler ─────────────────────────────────────────────────
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error", "type": type(exc).__name__},
    )

# ─── Routers ─────────────────────────────────────────────────────────────────
PREFIX = settings.API_PREFIX

protected = [Depends(get_principal)]
readers = [Depends(require_roles("viewer", "analyst", "admin"))]
app.include_router(health_router, prefix=PREFIX, dependencies=readers)
app.include_router(events_router, prefix=PREFIX, dependencies=protected)
app.include_router(containers_router, prefix=PREFIX, dependencies=readers)
app.include_router(incidents_router, prefix=PREFIX, dependencies=readers)
app.include_router(analytics_router, prefix=PREFIX, dependencies=readers)
app.include_router(model_router, prefix=PREFIX, dependencies=readers)
app.include_router(sensors_router, prefix=PREFIX, dependencies=protected)
app.include_router(audit_router, prefix=PREFIX, dependencies=protected)
if settings.DEMO_MODE_ENABLED:
    app.include_router(demo_router, prefix=PREFIX, dependencies=[Depends(require_roles("admin"))])

# ─── Root redirect ────────────────────────────────────────────────────────────
@app.get("/", include_in_schema=False)
async def root():
    return {
        "name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "docs": "/api/docs" if settings.APP_ENV != "production" else None,
        "health": "/api/health",
    }
