"""Regression tests for GitHub Actions dependency install strictness.

Every workflow in this repo installs dependencies with ``uv sync
--all-extras --dev``. Before this fix, none of those invocations passed
``--locked``, so if ``pyproject.toml`` and ``uv.lock`` ever drifted out of
sync -- say, a dependency bump landed in ``pyproject.toml`` without a
matching ``uv lock`` run -- CI would silently re-resolve dependencies at run
time instead of failing. That re-resolution can pull in a newer (and
potentially compromised) release that was never reviewed or pinned in the
lockfile, defeating the lockfile's supply-chain guarantee. ``uv sync
--locked`` instead fails loudly the moment the lockfile stops matching the
manifest.

This test parameterizes over every workflow file (not just ``ci.yml``), so
it also guards the "every dependency install is reproducible, or the job
fails" convention against regressing in any workflow, present or future.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

WORKFLOWS_DIR = Path(__file__).parent.parent / ".github" / "workflows"
WORKFLOW_FILES = sorted({*WORKFLOWS_DIR.glob("*.yml"), *WORKFLOWS_DIR.glob("*.yaml")})

_UV_SYNC_RE = re.compile(r"^\s*run:\s*(uv sync[^\n]*)$", re.MULTILINE)


def _uv_sync_commands(workflow_text: str) -> list[str]:
    """Return every ``run: uv sync ...`` command line found in a workflow file."""
    return [match.group(1) for match in _UV_SYNC_RE.finditer(workflow_text)]


class TestUvSyncStepsAreLocked:
    """Every ``uv sync`` install step, in every workflow, must pass ``--locked``.

    Before this fix, ``ci.yml`` and ``docs.yml`` ran ``uv sync --all-extras
    --dev`` with no ``--locked`` flag, so a stale ``uv.lock`` would be
    silently re-resolved instead of failing the job. This assertion would
    have failed against that version of those files.
    """

    @pytest.mark.unit
    @pytest.mark.parametrize("workflow_path", WORKFLOW_FILES, ids=lambda p: p.name)
    def test_all_uv_sync_steps_pass_locked(self, workflow_path: Path) -> None:
        commands = _uv_sync_commands(workflow_path.read_text())
        if not commands:
            pytest.skip(f"{workflow_path.name} has no 'uv sync' step")

        for command in commands:
            assert "--locked" in command.split(), (
                f"{workflow_path.name}: {command!r} does not pass --locked, "
                "so a stale uv.lock would be silently re-resolved instead of failing CI"
            )
