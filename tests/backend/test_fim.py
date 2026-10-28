"""
Unit Tests: File Integrity Monitoring (FIM) Service & Path Security
"""
import hashlib
import tempfile
from pathlib import Path

import pytest

from app.services.fim import (
    FIMPathSecurityError,
    FIMService,
    compute_streaming_sha256,
    matches_patterns,
    sanitize_watch_path,
)


def test_sanitize_watch_path():
    """Verify path sanitization and directory traversal protections."""
    with tempfile.TemporaryDirectory() as td:
        p = Path(td)
        assert sanitize_watch_path(str(p)) == p.resolve()

        # Nonexistent path
        with pytest.raises(FIMPathSecurityError):
            sanitize_watch_path(str(p / "nonexistent_subfolder"))

        # Empty path
        with pytest.raises(FIMPathSecurityError):
            sanitize_watch_path("")

        # Null byte in path
        with pytest.raises(FIMPathSecurityError):
            sanitize_watch_path(f"{td}\x00traversal")


def test_compute_streaming_sha256():
    """Verify 64KB streaming buffer SHA-256 computation against standard hashlib."""
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        data = b"Agni Threat Detection Engine Test Payload" * 5000  # ~200KB
        tf.write(data)
        tf_path = Path(tf.name)

    try:
        expected_hash = hashlib.sha256(data).hexdigest()
        computed_hash, err = compute_streaming_sha256(tf_path)

        assert err is None
        assert computed_hash == expected_hash

        # File exceeding max_size_bytes
        _, size_err = compute_streaming_sha256(tf_path, max_size_bytes=100)
        assert size_err == "EXCEEDS_MAX_FILE_SIZE"

    finally:
        if tf_path.exists():
            tf_path.unlink()


def test_matches_patterns():
    """Verify glob matching and exclusion patterns."""
    assert matches_patterns("kernel.sys", ["*.sys"])
    assert not matches_patterns("kernel.sys", ["*.exe"])
    assert matches_patterns("app.exe", ["*"], exclude_patterns=["*.tmp"])
    assert not matches_patterns("app.tmp", ["*"], exclude_patterns=["*.tmp"])


def test_fim_scan_and_diff_lifecycle():
    """Verify baseline creation and diff detection (created, modified, deleted)."""
    fim = FIMService()

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        file1 = root / "file1.txt"
        file2 = root / "file2.txt"

        file1.write_text("Hello Agni")
        file2.write_text("Configuration baseline")

        # 1. Initial Scan
        records = fim.scan_path(td)
        assert len(records) == 2

        baseline_map = {
            r.file_path: {
                "sha256_hash": r.sha256_hash,
                "file_size_bytes": r.file_size_bytes,
                "mtime": r.mtime,
            }
            for r in records
        }

        # 2. Modify file1, add file3, delete file2
        file1.write_text("Hello Agni Modified Content")
        file3 = root / "file3.txt"
        file3.write_text("Newly dropped artifact")
        file2.unlink()

        # 3. Second Scan & Diff
        current_records = fim.scan_path(td)
        assert len(current_records) == 2  # file1 and file3

        changes, events = fim.diff_baseline(baseline_map, current_records)

        change_types = {c["change_type"] for c in changes}
        assert "CREATED" in change_types
        assert "MODIFIED" in change_types
        assert "DELETED" in change_types

        # Verify corresponding events
        event_actions = {e["action"] for e in events}
        assert "created" in event_actions
        assert "modified" in event_actions
        assert "deleted" in event_actions
