"""Regression tests for pinning the ``uv`` binary that ``astral-sh/setup-uv`` installs.

``astral-sh/setup-uv`` is itself pinned to a full commit SHA in every
workflow (see ``test_workflow_pins.py``), but that only pins the *action*'s
code -- not the ``uv`` binary the action downloads and installs at run time.
Without an explicit, exact ``version:`` input, the action resolves and
installs whatever the latest ``uv`` release (or, with a range like
``">=0.9"``, the highest release matching that range) happens to be the
moment the workflow runs. A compromised or badly broken new ``uv`` release is
then picked up automatically by the next CI or docs run, with no repo change
or review.

Before this fix, every ``astral-sh/setup-uv`` step in ``ci.yml`` (4 jobs:
``dependency-audit``, ``validate``, ``test-smoke``, ``test-full``) and
``docs.yml`` omitted ``version:``, leaving that toolchain component mutable
despite the action pin. ``publish.yml`` already pinned an exact
``version: "0.9.11"`` (see ``TestSetupUvVersionIsPinned`` in
``test_workflow_build_publish_split.py``), matching the ``uv_build==0.9.11``
backend pinned in ``pyproject.toml`` -- this test extends that same exact
pin to every other workflow, and additionally checks every pin agrees with
that canonical version, so the two can't silently drift apart.

This test parameterizes over every workflow file, so it also guards the
"every setup-uv step pins an exact uv version, matching uv_build" convention
against regressing in any workflow, present or future.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
WORKFLOWS_DIR = REPO_ROOT / ".github" / "workflows"
WORKFLOW_FILES = sorted({*WORKFLOWS_DIR.glob("*.yml"), *WORKFLOWS_DIR.glob("*.yaml")})
PYPROJECT = REPO_ROOT / "pyproject.toml"

# Matches both `uses: astral-sh/setup-uv@...` and the quoted
# `uses: "astral-sh/setup-uv@..."` form.
_SETUP_UV_USES_RE = re.compile(r"""^\s*(?:-\s+)?uses:\s*["']?astral-sh/setup-uv@""")
# Requires an exact, quoted X.Y.Z scalar -- rejects `latest`, ranges like
# `">=0.9"`, empty/absent values, and `${{ ... }}` expressions, all of which
# leave the installed uv release mutable despite a `version:` key existing.
_VERSION_KEY_RE = re.compile(r'^\s*version:\s*"([0-9]+\.[0-9]+\.[0-9]+)"\s*$')


def _canonical_uv_version() -> str:
    """Return the exact ``uv_build`` version pinned in ``pyproject.toml``."""
    text = PYPROJECT.read_text()
    match = re.search(r'requires\s*=\s*\[\s*"uv_build==([0-9]+\.[0-9]+\.[0-9]+)"\s*\]', text)
    assert match, "pyproject.toml: could not find an exact 'uv_build==X.Y.Z' [build-system] requirement"
    return match.group(1)


def _indent(line: str) -> int:
    """Return a line's leading-whitespace width."""
    return len(line) - len(line.lstrip(" "))


def _key_indent(line: str) -> int:
    """Return the column at which this line's own YAML key starts.

    A step's first key is often written inline with its list bullet
    (``- uses: ...``); that key's siblings (``with:``, ``id:``, ...) then
    align with the text after the dash, not with the dash itself.
    """
    raw_indent = _indent(line)
    if line[raw_indent:].startswith("- "):
        return raw_indent + 2
    return raw_indent


def _with_block(lines: list[str], uses_index: int) -> list[str] | None:
    """Return the ``with:`` block's direct child lines for the step at ``uses_index``, or ``None``.

    Mirrors the parser in ``test_workflow_pins.py``: ``with:`` is a sibling
    key of ``uses:`` within the same step mapping, so it shares ``uses:``'s
    key indentation. This scans forward over any other sibling keys before
    finding it, and stops as soon as indentation drops below that level.
    """
    key_indent = _key_indent(lines[uses_index])
    index = uses_index + 1
    while index < len(lines):
        line = lines[index]
        if not line.strip():
            index += 1
            continue
        line_indent = _indent(line)
        if line_indent < key_indent:
            return None  # dedented out of the step: no with: block
        if line_indent == key_indent:
            if line.strip() == "with:":
                break
            index += 1  # another sibling key of uses:, keep scanning
            continue
        index += 1  # a scalar continuation of a prior sibling's value
    else:
        return None

    child_indent: int | None = None
    block: list[str] = []
    index += 1
    while index < len(lines):
        line = lines[index]
        if not line.strip():
            index += 1
            continue
        line_indent = _indent(line)
        if line_indent <= key_indent:
            break
        if child_indent is None:
            child_indent = line_indent
        if line_indent == child_indent:
            block.append(line)
        index += 1
    return block


class TestSetupUvStepsPinAnExactUvVersion:
    """Every ``astral-sh/setup-uv`` step, in every workflow, must pin an exact ``version:``
    that matches the canonical ``uv_build`` version in ``pyproject.toml``.

    Before this fix, ``ci.yml`` (4 jobs) and ``docs.yml`` invoked
    ``astral-sh/setup-uv`` with only ``enable-cache: true`` and no
    ``version:`` input, so each run installed whatever ``uv`` release was
    latest at run time. This assertion would have failed against that
    version of those files.
    """

    @pytest.mark.unit
    @pytest.mark.parametrize("workflow_path", WORKFLOW_FILES, ids=lambda p: p.name)
    def test_all_setup_uv_steps_pin_the_canonical_uv_version(self, workflow_path: Path) -> None:
        expected_version = _canonical_uv_version()
        lines = workflow_path.read_text().splitlines()
        setup_uv_indices = [i for i, line in enumerate(lines) if _SETUP_UV_USES_RE.match(line)]
        if not setup_uv_indices:
            pytest.skip(f"{workflow_path.name} has no astral-sh/setup-uv step")

        for index in setup_uv_indices:
            block = _with_block(lines, index)
            assert block is not None, (
                f"{workflow_path.name}: astral-sh/setup-uv step at line {index + 1} has no "
                "'with:' block, so it installs whatever uv release is latest at run time"
            )
            pinned_versions = [m.group(1) for line in block if (m := _VERSION_KEY_RE.match(line))]
            assert pinned_versions, (
                f"{workflow_path.name}: astral-sh/setup-uv step at line {index + 1} does not pin "
                "an exact, quoted 'version: \"X.Y.Z\"', so it installs whatever uv release is "
                "latest (or highest-matching, for a range) at run time"
            )
            assert pinned_versions == [expected_version], (
                f"{workflow_path.name}: astral-sh/setup-uv step at line {index + 1} pins uv "
                f"{pinned_versions!r}, not the canonical uv_build version {expected_version!r} "
                "from pyproject.toml -- these must move in lockstep"
            )
