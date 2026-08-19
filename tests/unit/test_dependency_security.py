"""Regression tests for known-vulnerable transitive dependency versions.

These tests guard against re-introducing dependency versions with known
security advisories via a stale or downgraded lock file.
"""

from __future__ import annotations

import importlib.metadata

from packaging.version import Version


def test_urllib3_not_affected_by_ghsa_mf9v_mfxr_j63j_and_ghsa_qccp_gfcp_xxvc() -> None:
    """urllib3 must be >= 2.7.0.

    Versions before 2.7.0 are affected by two High-severity advisories:
    - GHSA-mf9v-mfxr-j63j: decompression-bomb DoS via the streaming API.
    - GHSA-qccp-gfcp-xxvc: Authorization/Cookie header leak on cross-origin
      redirects via the low-level ProxyManager API.

    urllib3 is pulled in transitively via sphinx -> requests in the docs
    dependency group, so a stale lock file can silently reintroduce it.
    """
    installed_version = Version(importlib.metadata.version("urllib3"))

    assert installed_version >= Version("2.7.0"), (
        f"urllib3 {installed_version} is vulnerable to GHSA-mf9v-mfxr-j63j and "
        "GHSA-qccp-gfcp-xxvc; run `uv lock --upgrade-package urllib3` to update it."
    )
