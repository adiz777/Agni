"""
Agni File Integrity Monitoring (FIM) Service
Streaming SHA-256 baseline snapshots and change detection engine.
"""

import fnmatch
import hashlib
import os
import stat
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# Chunk size for streaming hash calculation: 64KB (65,536 bytes)
FIM_CHUNK_SIZE = 64 * 1024
DEFAULT_MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB


class FIMPathSecurityError(Exception):
    """Raised when an invalid or traversing watch path is requested."""
    pass


class FIMFileRecord:
    """In-memory representation of a baselined file."""
    def __init__(
        self,
        file_path: str,
        sha256_hash: str,
        file_size_bytes: int,
        mtime: datetime,
        permissions: str | None = None,
        owner: str | None = None,
        error: str | None = None,
    ) -> None:
        self.file_path = file_path
        self.sha256_hash = sha256_hash
        self.file_size_bytes = file_size_bytes
        self.mtime = mtime
        self.permissions = permissions
        self.owner = owner
        self.error = error

    def to_dict(self) -> dict[str, Any]:
        return {
            "file_path": self.file_path,
            "sha256_hash": self.sha256_hash,
            "file_size_bytes": self.file_size_bytes,
            "mtime": self.mtime.isoformat(),
            "permissions": self.permissions,
            "owner": self.owner,
            "error": self.error,
        }


def sanitize_watch_path(path_str: str) -> Path:
    """
    Validate and resolve canonical absolute watch path.
    Guards against relative traversal, null bytes, and non-existent targets.
    """
    if not path_str or not path_str.strip():
        raise FIMPathSecurityError("Watch path cannot be empty")

    if "\x00" in path_str:
        raise FIMPathSecurityError("Null byte detected in watch path")

    try:
        resolved = Path(path_str).expanduser().resolve()
    except Exception as e:
        raise FIMPathSecurityError(f"Malformed watch path: {e}") from e

    if not resolved.exists():
        raise FIMPathSecurityError(f"Target watch path does not exist: {resolved}")

    return resolved


def compute_streaming_sha256(
    file_path: Path, max_size_bytes: int = DEFAULT_MAX_FILE_SIZE
) -> tuple[str | None, str | None]:
    """
    Calculate SHA-256 hash using 64KB streaming buffer.

    Returns:
        Tuple of (sha256_hexdigest, error_message)
    """
    try:
        file_stat = file_path.stat()
        if file_stat.st_size > max_size_bytes:
            return None, "EXCEEDS_MAX_FILE_SIZE"

        if file_path.is_symlink():
            if not file_path.exists():
                return None, "BROKEN_SYMLINK"

        hasher = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(FIM_CHUNK_SIZE):
                hasher.update(chunk)

        return hasher.hexdigest(), None
    except PermissionError:
        return None, "PERMISSION_DENIED_LOCKED"
    except FileNotFoundError:
        return None, "FILE_NOT_FOUND"
    except OSError as err:
        return None, f"OS_IO_ERROR: {str(err)}"
    except Exception as err:
        return None, f"HASH_ERROR: {str(err)}"


def matches_patterns(
    filename: str, include_patterns: list[str], exclude_patterns: list[str] | None = None
) -> bool:
    """Evaluate whether filename matches include globs and avoids exclude globs."""
    if exclude_patterns:
        for pat in exclude_patterns:
            if fnmatch.fnmatch(filename, pat):
                return False

    if not include_patterns or "*" in include_patterns:
        return True

    return any(fnmatch.fnmatch(filename, pat) for pat in include_patterns)


class FIMService:
    """
    File Integrity Monitoring Service.
    Handles baseline creation, live scanning, and change diffing.
    """

    def scan_path(
        self,
        target_path: str,
        recursive: bool = True,
        file_patterns: list[str] | None = None,
        exclude_patterns: list[str] | None = None,
        max_file_size_bytes: int = DEFAULT_MAX_FILE_SIZE,
    ) -> list[FIMFileRecord]:
        """
        Scan a directory or single file, computing SHA-256 hashes and metadata.
        """
        root = sanitize_watch_path(target_path)
        patterns = file_patterns or ["*"]
        excludes = exclude_patterns or ["*.tmp", "*.log", "*.swp"]

        records: list[FIMFileRecord] = []

        if root.is_file():
            if matches_patterns(root.name, patterns, excludes):
                rec = self._hash_single_file(root, max_file_size_bytes)
                if rec:
                    records.append(rec)
            return records

        walker = root.rglob("*") if recursive else root.glob("*")
        for p in walker:
            try:
                if not p.is_file():
                    continue

                if not matches_patterns(p.name, patterns, excludes):
                    continue

                rec = self._hash_single_file(p, max_file_size_bytes)
                if rec:
                    records.append(rec)
            except (PermissionError, FileNotFoundError):
                continue
            except Exception:
                continue

        return records

    def _hash_single_file(self, path: Path, max_size_bytes: int) -> FIMFileRecord | None:
        try:
            st = path.stat()
            mtime = datetime.fromtimestamp(st.st_mtime, tz=UTC)
            perms = oct(stat.S_IMODE(st.st_mode))
            owner = str(getattr(st, "st_uid", "unknown"))

            sha, err = compute_streaming_sha256(path, max_size_bytes)
            return FIMFileRecord(
                file_path=str(path.resolve()),
                sha256_hash=sha or "UNHASHED_ERROR",
                file_size_bytes=st.st_size,
                mtime=mtime,
                permissions=perms,
                owner=owner,
                error=err,
            )
        except (PermissionError, FileNotFoundError):
            return None
        except Exception as err:
            return FIMFileRecord(
                file_path=str(path.resolve()),
                sha256_hash="ERROR",
                file_size_bytes=0,
                mtime=datetime.now(UTC),
                error=str(err),
            )

    def diff_baseline(
        self,
        baseline_entries: dict[str, dict[str, Any]],
        current_records: list[FIMFileRecord],
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """
        Compare current filesystem state against baselined state.

        Args:
            baseline_entries: Mapping of `file_path -> {sha256_hash, file_size_bytes, mtime}`
            current_records: List of freshly collected `FIMFileRecord` objects.

        Returns:
            Tuple of:
            1. `changes`: List of change dicts (CREATED, MODIFIED, DELETED, METADATA_CHANGED)
            2. `events`: Normalized telemetry event dictionaries ready for Varuna detection.
        """
        changes: list[dict[str, Any]] = []
        events: list[dict[str, Any]] = []
        now = datetime.now(UTC)

        current_map: dict[str, FIMFileRecord] = {r.file_path: r for r in current_records}

        # 1. Detect Created and Modified files
        for fpath, curr in current_map.items():
            if fpath not in baseline_entries:
                change = {
                    "file_path": fpath,
                    "change_type": "CREATED",
                    "previous_sha256": None,
                    "current_sha256": curr.sha256_hash,
                    "previous_size": None,
                    "current_size": curr.file_size_bytes,
                    "detected_at": now.isoformat(),
                }
                changes.append(change)
                events.append(self._build_fim_event("created", fpath, change, now))

            else:
                base = baseline_entries[fpath]
                base_hash = base.get("sha256_hash")
                curr_hash = curr.sha256_hash

                if base_hash != curr_hash and curr_hash not in ("ERROR", "UNHASHED_ERROR"):
                    change = {
                        "file_path": fpath,
                        "change_type": "MODIFIED",
                        "previous_sha256": base_hash,
                        "current_sha256": curr_hash,
                        "previous_size": base.get("file_size_bytes"),
                        "current_size": curr.file_size_bytes,
                        "detected_at": now.isoformat(),
                    }
                    changes.append(change)
                    events.append(self._build_fim_event("modified", fpath, change, now))

                elif base.get("file_size_bytes") != curr.file_size_bytes:
                    change = {
                        "file_path": fpath,
                        "change_type": "METADATA_CHANGED",
                        "previous_sha256": base_hash,
                        "current_sha256": curr_hash,
                        "previous_size": base.get("file_size_bytes"),
                        "current_size": curr.file_size_bytes,
                        "detected_at": now.isoformat(),
                    }
                    changes.append(change)
                    events.append(self._build_fim_event("modified", fpath, change, now, severity="Low"))

        # 2. Detect Deleted files
        for fpath, base in baseline_entries.items():
            if fpath not in current_map:
                change = {
                    "file_path": fpath,
                    "change_type": "DELETED",
                    "previous_sha256": base.get("sha256_hash"),
                    "current_sha256": None,
                    "previous_size": base.get("file_size_bytes"),
                    "current_size": None,
                    "detected_at": now.isoformat(),
                }
                changes.append(change)
                events.append(self._build_fim_event("deleted", fpath, change, now))

        return changes, events

    def _build_fim_event(
        self,
        action: str,
        file_path: str,
        change: dict[str, Any],
        timestamp: datetime,
        severity: str | None = None,
    ) -> dict[str, Any]:
        """Classify severity and construct normalized TelemetryEvent payload."""
        if severity is None:
            lower_path = file_path.lower()
            if any(crit in lower_path for crit in ["hosts", "system32", "/etc/shadow", "/etc/passwd", "/bin/"]):
                severity = "Critical"
            elif any(lower_path.endswith(ext) for ext in [".exe", ".dll", ".so", ".dylib", ".sys"]):
                severity = "High"
            elif any(lower_path.endswith(ext) for ext in [".conf", ".json", ".yaml", ".yml", ".ini"]):
                severity = "Medium"
            else:
                severity = "Low"

        import platform
        import sys

        return {
            "event_id": str(uuid.uuid4()),
            "timestamp": timestamp.isoformat(),
            "event_version": "1.0.0",
            "category": "file_integrity",
            "action": action,
            "severity": severity,
            "source": "fim",
            "host": {
                "hostname": os.environ.get("COMPUTERNAME", os.environ.get("HOSTNAME", platform.node())),
                "os": sys.platform,
            },
            "actor": {
                "name": "system",
                "pid": None,
            },
            "target": {
                "type": "file",
                "identifier": file_path,
                "details": change,
            },
            "details": {
                "change_type": change["change_type"],
                "previous_sha256": change["previous_sha256"],
                "current_sha256": change["current_sha256"],
            },
            "is_sample": False,
        }
