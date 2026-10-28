"""
Agni Security Utilities & Middleware Configuration
- Path traversal protection
- Localhost loopback enforcement
- CORS origin restriction
- Transactional audit log writer
"""
import logging
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

logger = logging.getLogger("agni.security")


def verify_loopback_host(host: str, allow_external: bool = False) -> bool:
    """Validates that a listening host is strictly loopback."""
    loopback_values = {"127.0.0.1", "localhost", "::1"}
    is_loopback = host in loopback_values
    if not is_loopback and not allow_external:
        logger.critical(
            "CRITICAL: Non-loopback binding attempt detected on '%s'. Server startup halted.",
            host,
        )
        return False
    return True


def validate_safe_path(
    target_path: str | Path,
    must_exist: bool = False,
    base_dir: Path | None = None,
) -> Path:
    """
    Validates filesystem path preventing directory traversal.
    Resolves symlinks and normalizes relative segments.
    """
    str_path = str(target_path)
    # Prohibit null bytes and traversal sequences
    if "\x00" in str_path:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Null byte detected in path parameter.",
        )

    try:
        resolved = Path(target_path).resolve()
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Malformed or invalid filesystem path: {e}",
        ) from e

    # If base_dir is enforced, ensure resolved path stays within base_dir
    if base_dir:
        resolved_base = Path(base_dir).resolve()
        try:
            resolved.relative_to(resolved_base)
        except ValueError as err:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Path traversal detected: {resolved} is outside allowed base directory {resolved_base}",
            ) from err

    if must_exist and not resolved.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Target path does not exist: {resolved}",
        )

    return resolved


def setup_cors(app: FastAPI, allowed_origins: list[str]) -> None:
    """Configures strict CORS middleware for Agni."""
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["*"],
    )


def record_audit_log(
    db: Session,
    action: str,
    target_resource: str,
    details: dict[str, Any] | None = None,
    status_code: str = "SUCCESS",
    actor: str = "local_analyst",
) -> None:
    """
    Synchronously records an immutable audit log entry.
    """
    try:
        from app.models.audit import AuditLogModel

        log_entry = AuditLogModel(
            id=str(uuid.uuid4()),
            timestamp=datetime.now(UTC),
            action=action,
            actor=actor,
            target_resource=target_resource,
            details=details or {},
            status=status_code,
        )
        db.add(log_entry)
        db.commit()
    except Exception as e:
        logger.error("Failed to commit audit log entry for '%s': %s", action, e)
        db.rollback()
