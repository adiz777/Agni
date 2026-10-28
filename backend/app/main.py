"""
Agni (अग्नि) Threat Detection Engine & Platform Entrypoint
FastAPI application, lifespan management, CORS security, and rule loading.
"""

import logging
import sys
from contextlib import asynccontextmanager
from datetime import UTC, datetime

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse

from app.api.router import api_router
from app.core.config import get_settings
from app.core.database import SessionLocal, init_db
from app.core.security import setup_cors, verify_loopback_host
from app.engine.detector import Detector

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("agni.main")
settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan manager.
    - Validates local loopback binding defense.
    - Initializes SQLite database schema in WAL mode.
    - Synchronizes 18 default defensive detection rules into DB.
    - Optionally seeds demo data if enabled by default.
    """
    logger.info("Starting Agni (अग्नि) Threat Detection Engine v%s", settings.VERSION)

    # 1. Enforce strict loopback binding
    if not verify_loopback_host(settings.HOST, settings.ALLOW_EXTERNAL_BIND):
        raise RuntimeError(
            f"Binding to host '{settings.HOST}' is prohibited without explicit authorization."
        )

    # 2. Initialize database schema
    init_db()

    # 3. Synchronize rules catalog
    db = SessionLocal()
    try:
        detector = Detector(rules_dir=settings.RULES_DIR)
        synced_rules = detector.sync_rules_to_db(db)
        logger.info("Successfully loaded and synchronized %d detection rules.", synced_rules)

        # 4. Seed demo data if configured
        if settings.DEMO_MODE_DEFAULT:
            from app.engine.correlator import IncidentCorrelator
            from app.engine.sample_generator import SampleDataGenerator

            correlator = IncidentCorrelator()
            generator = SampleDataGenerator(detector=detector, correlator=correlator)
            generator.seed_scenario(db)
            logger.info("Default demo mode active: Operation Ignis Vector seeded.")
    except Exception as e:
        logger.error("Error during startup initialization: %s", e, exc_info=True)
    finally:
        db.close()

    yield

    logger.info("Shutting down Agni Threat Detection Engine.")


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Cross-platform local-first threat detection and endpoint monitoring engine",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# Configure CORS whitelist
setup_cors(app, settings.CORS_ORIGINS)

# Mount master API router under /api/v1
app.include_router(api_router, prefix=settings.API_V1_STR)


@app.get("/health", tags=["Health"])
def root_health():
    """Root health probe returning quick status."""
    return {
        "status": "ok",
        "version": settings.VERSION,
        "timestamp": datetime.now(UTC).isoformat(),
    }


# Standard Error Format Handler
@app.exception_handler(HTTPException)
async def custom_http_exception_handler(request: Request, exc: HTTPException):
    """Formats HTTP exceptions according to standard error envelope."""
    error_code = "HTTP_ERROR"
    if exc.status_code == status.HTTP_404_NOT_FOUND:
        error_code = "RESOURCE_NOT_FOUND"
    elif exc.status_code == status.HTTP_400_BAD_REQUEST:
        error_code = "BAD_REQUEST"
    elif exc.status_code == status.HTTP_403_FORBIDDEN:
        error_code = "FORBIDDEN"
    elif exc.status_code == status.HTTP_409_CONFLICT:
        error_code = "CONFLICT"

    return JSONResponse(
        status_code=exc.status_code,
        content={
            "detail": exc.detail,
            "error_code": error_code,
            "timestamp": datetime.now(UTC).isoformat(),
        },
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    """Catches unhandled errors and returns consistent sanitized error JSON."""
    logger.error("Unhandled server exception: %s", exc, exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "detail": "An internal server error occurred.",
            "error_code": "INTERNAL_SERVER_ERROR",
            "timestamp": datetime.now(UTC).isoformat(),
        },
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=False,
    )
