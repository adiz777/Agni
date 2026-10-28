"""
FastAPI Route Dependencies & Singletons
"""
from functools import lru_cache

from fastapi import Depends

from app.core.database import get_db as get_db
from app.engine.correlator import IncidentCorrelator
from app.engine.detector import Detector
from app.engine.sample_generator import SampleDataGenerator
from app.platform import PlatformCollectorABC, get_platform_collector
from app.services.ai_assistant import AIAssistantService
from app.services.fim import FIMService


@lru_cache
def get_ai_service() -> AIAssistantService:
    return AIAssistantService()


@lru_cache
def get_detector() -> Detector:
    return Detector()


@lru_cache
def get_correlator() -> IncidentCorrelator:
    return IncidentCorrelator(dedup_window_seconds=300)


def get_collector() -> PlatformCollectorABC:
    return get_platform_collector()


@lru_cache
def get_fim_service() -> FIMService:
    return FIMService()


def get_sample_generator(
    detector: Detector = Depends(get_detector),
    correlator: IncidentCorrelator = Depends(get_correlator),
) -> SampleDataGenerator:
    return SampleDataGenerator(detector=detector, correlator=correlator)

