"""
Master API v1 Router Aggregation
"""
from fastapi import APIRouter

from app.api.ai import router as ai_router
from app.api.audit import router as audit_router
from app.api.demo import router as demo_router
from app.api.fim import router as fim_router
from app.api.health import router as health_router
from app.api.incidents import router as incidents_router
from app.api.reports import router as reports_router
from app.api.rules import router as rules_router
from app.api.settings import router as settings_router
from app.api.telemetry import router as telemetry_router

api_router = APIRouter()

api_router.include_router(health_router)
api_router.include_router(telemetry_router)
api_router.include_router(fim_router)
api_router.include_router(rules_router)
api_router.include_router(incidents_router)
api_router.include_router(reports_router)
api_router.include_router(audit_router)
api_router.include_router(settings_router)
api_router.include_router(demo_router)
api_router.include_router(ai_router)

