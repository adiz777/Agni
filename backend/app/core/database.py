"""
Agni SQLite WAL Mode Database Engine & Session Management
"""
import logging
from collections.abc import Generator

from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.core.config import get_settings

logger = logging.getLogger("agni.database")
settings = get_settings()

db_url = settings.get_database_url()

# Engine creation: check_same_thread=False allows FastAPI multi-threaded requests
engine = create_engine(
    db_url,
    connect_args={"check_same_thread": False, "timeout": 30.0},
    echo=False,
)


@event.listens_for(engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    """
    Configure high-performance concurrent SQLite pragmas:
    - WAL journal mode: readers do not block writers, writers do not block readers.
    - synchronous=NORMAL: optimal balance of integrity and speed in WAL mode.
    - foreign_keys=ON: enforces referential integrity.
    - busy_timeout=5000: wait up to 5 seconds if a lock occurs before failing.
    - cache_size=-64000: 64MB memory page cache.
    """
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL;")
    cursor.execute("PRAGMA synchronous=NORMAL;")
    cursor.execute("PRAGMA foreign_keys=ON;")
    cursor.execute("PRAGMA busy_timeout=5000;")
    cursor.execute("PRAGMA cache_size=-64000;")
    cursor.close()


SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    """Base declarative class for all SQLAlchemy 2.0 ORM models."""
    pass


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency yielding transactional database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Create all database tables and ensure directory layout."""
    settings.ensure_directories()
    # Import all models to ensure they are registered with Base.metadata
    import app.models  # noqa: F401
    Base.metadata.create_all(bind=engine)
    logger.info("Agni SQLite database schema initialized with WAL mode enabled.")
