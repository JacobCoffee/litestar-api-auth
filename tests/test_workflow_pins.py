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


_CHECKOUT_USES_RE = re.compile(r"^\s*uses:\s*actions/checkout@")


def _indent(line: str) -> int:
    """Return a line's leading-whitespace width."""
    return len(line) - len(line.lstrip(" "))


def _with_block(lines: list[str], uses_index: int) -> list[str] | None:
    """Return the ``with:`` block's child lines for the step at ``uses_index``, or ``None``.

    ``with:`` is a sibling key of ``uses:`` within the same step mapping, so it
    shares the step's indentation; its own children are indented one level
    further and run until the next line at or below that indentation.
    """
    uses_indent = _indent(lines[uses_index])
    index = uses_index + 1
    while index < len(lines) and not lines[index].strip():
        index += 1
    if index >= len(lines) or _indent(lines[index]) != uses_indent or lines[index].strip() != "with:":
        return None

    with_indent = uses_indent
    block: list[str] = []
    index += 1
    while index < len(lines):
        line = lines[index]
        if line.strip() and _indent(line) <= with_indent:
            break
        block.append(line)
        index += 1
    return block


class TestCheckoutStepsDisablePersistCredentials:
    """Every ``actions/checkout`` step, in every workflow, must set ``persist-credentials: false``.

    Before this fix, ``publish.yml``'s checkout step had no ``with:`` block at
    all, so it kept ``actions/checkout``'s default of
    ``persist-credentials: true`` -- the release job's ``GITHUB_TOKEN`` git
    credential was left on disk in ``.git/config`` for every later step
    (``uv build``, the PyPI publish action) to read, unlike every other
    workflow in the repo, which already disables it. This assertion would
    have failed against that version of the file.
    """

    @pytest.mark.unit
    @pytest.mark.parametrize("workflow_path", WORKFLOW_FILES, ids=lambda p: p.name)
    def test_checkout_steps_set_persist_credentials_false(self, workflow_path: Path) -> None:
        lines = workflow_path.read_text().splitlines()
        checkout_indices = [i for i, line in enumerate(lines) if _CHECKOUT_USES_RE.match(line)]
        if not checkout_indices:
            pytest.skip(f"{workflow_path.name} has no actions/checkout step")

        for index in checkout_indices:
            block = _with_block(lines, index)
            assert block is not None, (
                f"{workflow_path.name}: actions/checkout step at line {index + 1} has no "
                "'with:' block, so it keeps the default persist-credentials: true"
            )
            assert any(line.strip() == "persist-credentials: false" for line in block), (
                f"{workflow_path.name}: actions/checkout step at line {index + 1} does not "
                "set persist-credentials: false"
            )


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
