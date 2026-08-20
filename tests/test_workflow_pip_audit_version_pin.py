"""Regression test for the floating ``pip-audit`` version inside a SHA-pinned action.

``pypa/gh-action-pip-audit`` is pinned to a full commit SHA in ``ci.yml``'s
``dependency-audit`` job, but that only pins the *action*'s own code. At run
time, the action unconditionally does ``pip install -r <its own
requirements.txt>``, and that file constrains ``pip-audit ~=2.0,>=2.5.6`` --
a floating range, not an exact version. So every run installs whatever
``pip-audit`` release currently satisfies that range, regardless of the SHA
pin on the action wrapping it. A malicious ``pip-audit`` 2.x release (or a
compromised transitive dependency of it) would be installed and executed by
the very job meant to catch known-vulnerable dependencies, silently
neutering the audit gate with no repo change or review.

The fix pre-installs an exact-pinned ``pip-audit==X.Y.Z`` into a dedicated
venv (a step preceding the action) and points the action at that venv via its
``virtual-environment`` input. Because the action's own install step is a
plain ``pip install`` (no ``--upgrade``/``--force-reinstall``), it treats an
already-satisfying, already-installed ``pip-audit`` as a no-op instead of
replacing it -- so the actual version invoked is the one this repo pinned,
not whatever the action's floating requirements.txt would otherwise resolve.

This test would have failed against the pre-fix file, which had no step
installing a pinned ``pip-audit`` and no ``virtual-environment`` input on the
``pypa/gh-action-pip-audit`` step -- leaving the executed ``pip-audit``
version fully unpinned despite the action SHA pin.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"

_JOB_HEADER_RE = re.compile(r"^  ([A-Za-z0-9_-]+):[ \t]*$", re.MULTILINE)
_PIP_AUDIT_PIN_RE = re.compile(r"pip-audit==([0-9]+\.[0-9]+(?:\.[0-9]+)?)")
_VENV_DIR_RE = re.compile(r"uv\s+venv\s+(\S+)")
# Matches only the actual `uses:` invocation, not this action's name appearing
# in a comment (e.g. one explaining *why* a preceding step exists).
_ACTION_USES_RE = re.compile(r"^\s*(?:-\s+)?uses:\s*pypa/gh-action-pip-audit@", re.MULTILINE)


def _job_blocks(text: str) -> dict[str, str]:
    """Split the ``jobs:`` mapping into ``{job_name: block_text}``."""
    jobs_index = text.find("\njobs:")
    assert jobs_index != -1, "ci.yml has no 'jobs:' key"
    jobs_text = text[jobs_index + 1 :]
    headers = list(_JOB_HEADER_RE.finditer(jobs_text))
    blocks: dict[str, str] = {}
    for i, header in enumerate(headers):
        end = headers[i + 1].start() if i + 1 < len(headers) else len(jobs_text)
        blocks[header.group(1)] = jobs_text[header.start() : end]
    return blocks


@pytest.fixture
def dependency_audit_job() -> str:
    jobs = _job_blocks(CI_WORKFLOW.read_text())
    job = jobs.get("dependency-audit")
    assert job is not None, "ci.yml: expected a 'dependency-audit' job"
    return job


class TestPipAuditVersionIsPinned:
    """The actual ``pip-audit`` executed must be pinned, not left to the action's floating range."""

    @pytest.mark.unit
    def test_a_step_installs_an_exact_pinned_pip_audit(self, dependency_audit_job: str) -> None:
        match = _PIP_AUDIT_PIN_RE.search(dependency_audit_job)
        assert match is not None, (
            "ci.yml: 'dependency-audit' job has no step installing an exact "
            "'pip-audit==X.Y.Z' -- the version actually executed floats on "
            "pypa/gh-action-pip-audit's own 'pip-audit ~=2.0,>=2.5.6' requirement "
            "despite the action itself being SHA-pinned"
        )

    @pytest.mark.unit
    def test_pinned_pip_audit_install_precedes_the_action_step(self, dependency_audit_job: str) -> None:
        pin_match = _PIP_AUDIT_PIN_RE.search(dependency_audit_job)
        assert pin_match is not None, "ci.yml: expected a 'pip-audit==X.Y.Z' pin in 'dependency-audit'"

        action_match = _ACTION_USES_RE.search(dependency_audit_job)
        assert action_match is not None, (
            "ci.yml: expected a 'uses: pypa/gh-action-pip-audit@...' step in 'dependency-audit'"
        )
        action_index = action_match.start()

        assert pin_match.start() < action_index, (
            "ci.yml: the pinned 'pip-audit==X.Y.Z' install runs after the "
            "pypa/gh-action-pip-audit step, so it can't influence what that "
            "step actually installs and executes"
        )

    @pytest.mark.unit
    def test_pip_audit_action_step_points_at_the_pinned_venv(self, dependency_audit_job: str) -> None:
        """The action must be told to reuse the pre-pinned venv via ``virtual-environment``.

        Without this input, the action installs its floating ``pip-audit``
        requirement into a fresh default environment, ignoring any venv this
        job set up earlier -- so an exact pin elsewhere in the job would be
        installed but never actually used.
        """
        venv_match = _VENV_DIR_RE.search(dependency_audit_job)
        assert venv_match is not None, (
            "ci.yml: 'dependency-audit' job has no 'uv venv <dir>' step to hold a pinned pip-audit"
        )
        venv_dir = venv_match.group(1)

        action_match = _ACTION_USES_RE.search(dependency_audit_job)
        assert action_match is not None, (
            "ci.yml: expected a 'uses: pypa/gh-action-pip-audit@...' step in 'dependency-audit'"
        )
        step_text = dependency_audit_job[action_match.start() : action_match.start() + 400]

        venv_input_match = re.search(r"^\s*virtual-environment:\s*(\S+)\s*$", step_text, re.MULTILINE)
        assert venv_input_match is not None, (
            "ci.yml: the pypa/gh-action-pip-audit step has no 'virtual-environment:' "
            "input, so it ignores any pre-pinned pip-audit venv and falls back to "
            "installing its own floating 'pip-audit ~=2.0,>=2.5.6' into a fresh environment"
        )
        assert venv_input_match.group(1) == venv_dir, (
            f"ci.yml: pypa/gh-action-pip-audit's 'virtual-environment: {venv_input_match.group(1)}' "
            f"does not match the venv pinned pip-audit was installed into ({venv_dir!r})"
        )
