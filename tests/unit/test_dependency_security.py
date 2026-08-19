"""Regression tests for known-vulnerable transitive dependency versions.

These tests guard against re-introducing dependency versions with known
security advisories via a stale or downgraded lock file.
"""

from __future__ import annotations

import importlib.metadata
import sys
from pathlib import Path

import pytest
from packaging.version import Version

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

_LOCK_FILE = Path(__file__).parents[2] / "uv.lock"

_URLLIB3_MIN_VERSION = Version("2.7.0")
"""Versions below this are vulnerable to:

- GHSA-mf9v-mfxr-j63j: decompression-bomb DoS via the streaming API
  (affects urllib3 >=2.6.0,<2.7.0).
- GHSA-qccp-gfcp-xxvc: Authorization/Cookie header leak on cross-origin
  redirects via the low-level ProxyManager API (affects urllib3
  >=1.23,<2.7.0).

Both are fixed in urllib3 2.7.0.
"""


def test_uv_lock_pins_urllib3_above_vulnerable_versions() -> None:
    """uv.lock must not pin a urllib3 affected by GHSA-mf9v-mfxr-j63j /
    GHSA-qccp-gfcp-xxvc.

    urllib3 is pulled in transitively via sphinx -> requests in the docs
    dependency group, so this reads the lock file directly rather than the
    currently-installed environment: it catches a regression even if the
    local `.venv` happens to be out of sync with `uv.lock`.
    """
    lock_data = tomllib.loads(_LOCK_FILE.read_text())
    urllib3_entries = [pkg for pkg in lock_data["package"] if pkg["name"] == "urllib3"]

    assert urllib3_entries, "urllib3 not found in uv.lock; expected it as a transitive dependency"

    for entry in urllib3_entries:
        locked_version = Version(entry["version"])
        assert locked_version >= _URLLIB3_MIN_VERSION, (
            f"uv.lock pins urllib3 {locked_version}, which is vulnerable to "
            "GHSA-mf9v-mfxr-j63j and/or GHSA-qccp-gfcp-xxvc; run "
            "`uv lock --upgrade-package urllib3` to update it."
        )


def test_installed_urllib3_above_vulnerable_versions() -> None:
    """The synced environment must match the lock file's fixed urllib3.

    Complements the uv.lock check above by catching an environment that
    drifted from the lock file (e.g. `.venv` synced before the lock was
    upgraded).
    """
    try:
        installed_version = Version(importlib.metadata.version("urllib3"))
    except importlib.metadata.PackageNotFoundError:
        pytest.skip("urllib3 not installed (docs dependency group not synced)")

    assert installed_version >= _URLLIB3_MIN_VERSION, (
        f"urllib3 {installed_version} is vulnerable to GHSA-mf9v-mfxr-j63j "
        "and/or GHSA-qccp-gfcp-xxvc; run `uv sync` to match the updated lock file."
    )
