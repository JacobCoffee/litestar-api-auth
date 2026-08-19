"""Regression tests for GitHub Actions supply-chain pinning.

The release workflow (``publish.yml``) runs with ``id-token: write`` so it can
mint the OIDC token PyPI's Trusted Publishing trusts for this repo. Before this
fix, its steps referenced actions by mutable tag/branch (``@v6``, ``@v7``,
``@release/v1``) instead of a pinned commit SHA like every other workflow in
the repo. A compromised tag or the moving ``release/v1`` branch of any of
those actions would run arbitrary code inside that privileged job -- able to
steal the OIDC token or tamper with the built wheel/sdist before it reaches
PyPI.

This test parameterizes over every workflow file (not just ``publish.yml``),
so it also guards the repo-wide "pin everything to a full commit SHA"
convention against regressing in any other workflow, present or future --
including any workflow that later gains ``id-token: write``.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

WORKFLOWS_DIR = Path(__file__).parent.parent / ".github" / "workflows"
WORKFLOW_FILES = sorted(WORKFLOWS_DIR.glob("*.yml"))

_FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_USES_RE = re.compile(r"^\s*(?:-\s+)?uses:\s*([^\s#]+)")


def _uses_refs(workflow_text: str) -> list[str]:
    """Return every ``uses: <action>@<ref>`` value found in a workflow file."""
    return [match.group(1) for line in workflow_text.splitlines() if (match := _USES_RE.match(line))]


class TestWorkflowActionsArePinned:
    """Every ``uses:`` step, in every workflow, must be pinned to a full commit SHA.

    Before the fix, ``publish.yml`` referenced ``actions/checkout@v6``,
    ``actions/setup-python@v6``, ``astral-sh/setup-uv@v7``, and
    ``pypa/gh-action-pypi-publish@release/v1`` -- all mutable refs; this
    assertion would have failed against that version of the file.
    """

    @pytest.mark.unit
    @pytest.mark.parametrize("workflow_path", WORKFLOW_FILES, ids=lambda p: p.name)
    def test_all_actions_are_pinned_to_a_full_commit_sha(self, workflow_path: Path) -> None:
        refs = _uses_refs(workflow_path.read_text())
        assert refs, f"expected at least one 'uses:' step in {workflow_path.name}"

        for ref in refs:
            action, _, pinned = ref.partition("@")
            assert pinned, f"{workflow_path.name}: {action} has no pinned ref at all"
            assert _FULL_SHA_RE.match(
                pinned
            ), f"{workflow_path.name}: {action} is pinned to {pinned!r}, not a full commit SHA"
