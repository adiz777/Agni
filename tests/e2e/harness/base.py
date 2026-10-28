"""Base TestCase class for all Agni E2E tests.

Manages connection to live Agni backend or automatic fallback to the integrated reference server.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import unittest

from tests.e2e.harness.client import AgniAPIClient
from tests.e2e.harness.server import STATE, ReferenceServerManager


class AgniE2ETestCase(unittest.TestCase):
    """Base test case providing an initialized, opaque-box AgniAPIClient."""

    client: AgniAPIClient
    _server_manager: ReferenceServerManager | None = None
    _temp_dirs: list[str] = []

    @classmethod
    def setUpClass(cls) -> None:
        """Initialize client against live server or start reference server."""
        api_url = os.environ.get("AGNI_API_URL")

        if api_url:
            cls.client = AgniAPIClient(base_url=api_url)
        else:
            # Check if default 127.0.0.1:8000/api/v1 is responsive
            default_client = AgniAPIClient("http://127.0.0.1:8000/api/v1", timeout=1.0)
            try:
                resp = default_client.get_health()
                if resp.is_success:
                    cls.client = default_client
                    return
            except Exception:
                pass

            # Fall back to starting the integrated reference server
            cls._server_manager = ReferenceServerManager(host="127.0.0.1", port=0)
            mock_url = cls._server_manager.start()
            cls.client = AgniAPIClient(base_url=mock_url)

    @classmethod
    def tearDownClass(cls) -> None:
        """Tear down reference server if started."""
        if cls._server_manager:
            cls._server_manager.stop()
            cls._server_manager = None

    def setUp(self) -> None:
        """Reset mock state before each test if using in-process server."""
        if self._server_manager:
            STATE.reset()
        self._temp_dirs = []

    def tearDown(self) -> None:
        """Clean up any temporary directories created during test."""
        for d in self._temp_dirs:
            if os.path.exists(d):
                try:
                    shutil.rmtree(d, ignore_errors=True)
                except Exception:
                    pass
        self._temp_dirs.clear()

    def create_temp_directory(self) -> str:
        """Create a temporary directory tracked for automatic cleanup."""
        d = tempfile.mkdtemp(prefix="agni_test_")
        self._temp_dirs.append(d)
        return d
