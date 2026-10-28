"""
Pytest Fixtures for Agni Backend Test Suite
"""
import os
import sys
import tempfile
from pathlib import Path

import pytest

# Ensure backend directory is in sys.path
backend_dir = Path(__file__).resolve().parent.parent.parent / "backend"
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from app.core.config import get_settings
from app.core.database import Base, get_db
from app.engine.detector import Detector
from app.main import app


@pytest.fixture(scope="session")
def test_settings():
    return get_settings()


@pytest.fixture(scope="function")
def test_db():
    """Create a temporary SQLite database with WAL pragmas for testing."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        db_path = tf.name

    test_engine = create_engine(
        f"sqlite:///{Path(db_path).as_posix()}",
        connect_args={"check_same_thread": False},
    )

    @event.listens_for(test_engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL;")
        cursor.execute("PRAGMA synchronous=NORMAL;")
        cursor.execute("PRAGMA foreign_keys=ON;")
        cursor.close()

    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)
    Base.metadata.create_all(bind=test_engine)

    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()
        test_engine.dispose()
        if os.path.exists(db_path):
            try:
                os.remove(db_path)
            except OSError:
                pass


@pytest.fixture(scope="function")
def client(test_db):
    """FastAPI TestClient with overridden database session."""
    def override_get_db():
        try:
            yield test_db
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db

    # Also synchronize detection rules into test_db
    detector = Detector()
    detector.sync_rules_to_db(test_db)

    with TestClient(app) as test_client:
        yield test_client

    app.dependency_overrides.clear()
