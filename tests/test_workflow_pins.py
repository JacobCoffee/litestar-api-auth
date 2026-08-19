"""Regression tests for GitHub Actions supply-chain pinning.

The release workflow (``publish.yml``) runs with ``id-token: write`` so it can
mint the OIDC token PyPI's Trusted Publishing trusts for this repo. Before this
fix, its steps referenced actions by mutable tag/branch (``@v6``, ``@v7``,
``@release/v1``) instead of a pinned commit SHA like every other workflow in
the repo. A compromised tag or the moving ``release/v1`` branch of any of
those actions would run arbitrary code inside that privileged job -- able to
steal the OIDC token or tamper with the built wheel/sdist before it reaches
PyPI. These tests fail on any workflow step, in any job holding
``id-token: write``, that isn't pinned to a full 40-character commit SHA.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

WORKFLOWS_DIR = Path(__file__).parent.parent / ".github" / "workflows"

_FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_USES_RE = re.compile(r"^\s*(?:-\s+)?uses:\s*([^\s#]+)")


def _uses_refs(workflow_text: str) -> list[str]:
    """Return every ``uses: <action>@<ref>`` value found in a workflow file."""
    return [match.group(1) for line in workflow_text.splitlines() if (match := _USES_RE.match(line))]


class TestPublishWorkflowActionsArePinned:
    """Regression tests for the PyPI Trusted Publishing job (``id-token: write``)."""

    @pytest.fixture
    def publish_workflow_text(self) -> str:
        path = WORKFLOWS_DIR / "publish.yml"
        assert path.exists(), f"Workflow not found: {path}"
        return path.read_text()

    @pytest.mark.unit
    def test_all_actions_are_pinned_to_a_full_commit_sha(self, publish_workflow_text: str) -> None:
        """Every action used by the release job must be pinned to a 40-char commit SHA.

        Before the fix, ``actions/checkout@v6``, ``actions/setup-python@v6``,
        ``astral-sh/setup-uv@v7``, and ``pypa/gh-action-pypi-publish@release/v1``
        were all mutable refs; this assertion would have failed against that
        version of the file.
        """
        refs = _uses_refs(publish_workflow_text)
        assert refs, "expected at least one 'uses:' step in publish.yml"

        for ref in refs:
            action, _, pinned = ref.partition("@")
            assert pinned, f"{action} has no pinned ref at all"
            assert _FULL_SHA_RE.match(pinned), f"{action} is pinned to {pinned!r}, not a full commit SHA"

    @pytest.mark.unit
    def test_no_action_uses_a_known_mutable_ref(self, publish_workflow_text: str) -> None:
        """Guard against regressing back to the specific mutable refs that were vulnerable."""
        for mutable_ref in ("@v6", "@v7", "@release/v1"):
            assert mutable_ref not in publish_workflow_text
