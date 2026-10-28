"""
Unit Tests: Security Controls (Localhost Binding, Path Traversal, CORS & Audit Logging)
"""
import tempfile
from pathlib import Path

import pytest
from fastapi import HTTPException

from app.core.security import (
    record_audit_log,
    validate_safe_path,
    verify_loopback_host,
)
from app.models.audit import AuditLogModel


def test_verify_loopback_host():
    """Verify strictly localhost loopback host strings are allowed."""
    assert verify_loopback_host("127.0.0.1") is True
    assert verify_loopback_host("localhost") is True
    assert verify_loopback_host("::1") is True

    # External binding attempts must be rejected
    assert verify_loopback_host("0.0.0.0") is False
    assert verify_loopback_host("192.168.1.50") is False
    assert verify_loopback_host("8.8.8.8") is False

    # Allowed only with explicit override
    assert verify_loopback_host("0.0.0.0", allow_external=True) is True


def test_path_traversal_prevention():
    """Verify path traversal sequences and null bytes are rejected."""
    with tempfile.TemporaryDirectory() as td:
        base = Path(td)
        sub = base / "allowed"
        sub.mkdir()
        secret = base / "secret.txt"
        secret.write_text("classified")

        # Valid path inside base
        valid = validate_safe_path(sub, base_dir=base)
        assert valid == sub.resolve()

        # Path traversal out of base_dir
        with pytest.raises(HTTPException) as exc_info:
            validate_safe_path(sub / ".." / ".." / "outside", base_dir=sub)
        assert exc_info.value.status_code == 403

        # Null byte injection
        with pytest.raises(HTTPException) as exc_info:
            validate_safe_path(f"{td}\x00file.exe")
        assert exc_info.value.status_code == 400


def test_audit_log_recording(test_db):
    """Verify audit log records actions with timestamp and actor."""
    record_audit_log(
        db=test_db,
        action="TEST_ACTION",
        target_resource="system:unit_test",
        details={"key": "value"},
        status_code="SUCCESS",
        actor="test_runner",
    )

    log = test_db.query(AuditLogModel).filter(AuditLogModel.action == "TEST_ACTION").first()
    assert log is not None
    assert log.actor == "test_runner"
    assert log.target_resource == "system:unit_test"
    assert log.details == {"key": "value"}
    assert log.status == "SUCCESS"


def test_cors_headers(client):
    """Verify CORS preflight and origin headers on API."""
    response = client.options(
        "/api/v1/health",
        headers={
            "Origin": "http://127.0.0.1:5173",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == "http://127.0.0.1:5173"
