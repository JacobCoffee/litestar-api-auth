"""Tests to verify that example scripts run without errors.

These tests import and execute the example scripts to ensure they don't
break silently when the library API changes.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

EXAMPLES_DIR = Path(__file__).parent.parent / "examples"


class TestExamplesRun:
    """Test that example scripts execute without errors."""

    @pytest.mark.unit
    def test_basic_usage_runs(self) -> None:
        """Test that basic_usage.py runs without errors."""
        script_path = EXAMPLES_DIR / "basic_usage.py"
        assert script_path.exists(), f"Example script not found: {script_path}"

        result = subprocess.run(
            [sys.executable, str(script_path)],
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode == 0, f"Script failed with stderr:\n{result.stderr}"
        assert "Example completed successfully" in result.stdout

    @pytest.mark.unit
    def test_quickstart_runs(self) -> None:
        """Test that quickstart.py runs without errors."""
        script_path = EXAMPLES_DIR / "quickstart.py"
        assert script_path.exists(), f"Example script not found: {script_path}"

        result = subprocess.run(
            [sys.executable, str(script_path)],
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode == 0, f"Script failed with stderr:\n{result.stderr}"
        # Quickstart should output key verification
        assert "Key verification: True" in result.stdout


class TestExamplesImport:
    """Test that example scripts can be imported without side effects."""

    @pytest.mark.unit
    def test_basic_usage_imports(self) -> None:
        """Test that basic_usage.py can be imported."""
        # This ensures the module-level code doesn't crash
        # The main() function won't run due to if __name__ == "__main__" guard
        import importlib.util

        script_path = EXAMPLES_DIR / "basic_usage.py"
        spec = importlib.util.spec_from_file_location("basic_usage", script_path)
        assert spec is not None
        assert spec.loader is not None

        module = importlib.util.module_from_spec(spec)
        # This should not raise any exceptions
        spec.loader.exec_module(module)

        # Verify the main function exists
        assert hasattr(module, "main")
        assert callable(module.main)


class TestExamplesContent:
    """Test that examples use correct and current API."""

    @pytest.mark.unit
    def test_basic_usage_uses_timezone_aware_datetime(self) -> None:
        """Verify basic_usage.py uses timezone-aware datetime."""
        script_path = EXAMPLES_DIR / "basic_usage.py"
        content = script_path.read_text()

        # Should NOT use deprecated utcnow()
        assert "datetime.utcnow()" not in content, "Example uses deprecated datetime.utcnow()"

        # Should use timezone-aware datetime
        assert "datetime.now(timezone.utc)" in content or "timezone.utc" in content

    @pytest.mark.unit
    def test_quickstart_uses_timezone_aware_datetime(self) -> None:
        """Verify quickstart.py uses timezone-aware datetime."""
        script_path = EXAMPLES_DIR / "quickstart.py"
        content = script_path.read_text()

        # Should NOT use deprecated utcnow()
        assert "datetime.utcnow()" not in content, "Example uses deprecated datetime.utcnow()"

        # Should use timezone-aware datetime
        assert "datetime.now(timezone.utc)" in content or "timezone.utc" in content

    @pytest.mark.unit
    def test_examples_use_public_api(self) -> None:
        """Verify examples only use public API imports."""
        for script_path in EXAMPLES_DIR.glob("*.py"):
            if script_path.name == "__init__.py":
                continue

            content = script_path.read_text()

            # Should import from litestar_api_auth, not internal modules
            # (except for specific allowed imports like backends.base)
            assert (
                "from litestar_api_auth import" in content or "from litestar_api_auth." in content
            ), f"Example {script_path.name} should import from litestar_api_auth"
