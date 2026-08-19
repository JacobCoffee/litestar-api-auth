"""Regression test for CI's missing dependency vulnerability audit.

Before this fix, ``ci.yml``'s ``security`` job ran only ``zizmor`` --  a
GitHub Actions *workflow* linter. It never inspected the project's own
dependencies, so a newly published advisory against an already-locked
package (e.g. a CVE landing against a pinned ``litestar`` or ``multipart``
release well after ``uv.lock`` was generated) would never surface in CI. A
vulnerable pin could sit in ``uv.lock`` indefinitely, undetected, until
someone happened to run an audit tool by hand.

The fix adds two steps to the ``security`` job: one that exports the locked
dependency set from ``uv.lock`` to a requirements-style file (so the audit
covers exactly what would actually be installed, not whatever ``pyproject.toml``
alone would re-resolve to), and one that runs ``pypa/gh-action-pip-audit``
against that export. This test would have failed against the pre-fix file,
which had no ``uv export`` step and no ``pip-audit`` reference anywhere in
``ci.yml``.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"

_JOB_HEADER_RE = re.compile(r"^  ([A-Za-z0-9_-]+):[ \t]*$", re.MULTILINE)
_USES_RE = re.compile(r"^\s*(?:-\s+)?uses:\s*([^\s#]+)", re.MULTILINE)
_FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


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


def _uses_refs(block: str) -> list[str]:
    """Return every ``uses: <action>@<ref>`` value found in a job block."""
    return _USES_RE.findall(block)


class TestSecurityJobAuditsDependencies:
    """The ``security`` job must scan locked dependencies for known vulnerabilities, not just workflow files."""

    @pytest.mark.unit
    def test_security_job_still_runs_zizmor(self) -> None:
        """Sanity check that the scenario this test guards against still applies."""
        jobs = _job_blocks(CI_WORKFLOW.read_text())
        security_job = jobs.get("security")
        assert security_job is not None, "ci.yml: expected a 'security' job"
        assert "zizmorcore/zizmor-action" in security_job, (
            "ci.yml: 'security' job no longer runs zizmor; re-evaluate whether the "
            "dependency-audit addition below is still needed alongside it"
        )

    @pytest.mark.unit
    def test_security_job_exports_the_locked_dependency_set(self) -> None:
        jobs = _job_blocks(CI_WORKFLOW.read_text())
        security_job = jobs.get("security")
        assert security_job is not None, "ci.yml: expected a 'security' job"

        export_match = re.search(r"^\s*run:\s*(uv export[^\n]*)$", security_job, re.MULTILINE)
        assert export_match is not None, (
            "ci.yml: 'security' job has no 'uv export' step, so there is nothing for "
            "a dependency-audit tool to scan that reflects the actual locked pins"
        )
        command = export_match.group(1)
        assert "--locked" in command.split(), (
            f"ci.yml: {command!r} does not pass --locked, so the export could silently "
            "diverge from uv.lock instead of failing when the lockfile is stale"
        )

    @pytest.mark.unit
    def test_security_job_runs_a_dependency_audit(self) -> None:
        jobs = _job_blocks(CI_WORKFLOW.read_text())
        security_job = jobs.get("security")
        assert security_job is not None, "ci.yml: expected a 'security' job"

        refs = _uses_refs(security_job)
        audit_refs = [ref for ref in refs if "pip-audit" in ref.partition("@")[0]]
        assert audit_refs, (
            "ci.yml: 'security' job has no pip-audit (or equivalent dependency-audit) "
            "step, so advisories against already-locked dependencies never surface in CI"
        )

        for ref in audit_refs:
            action, _, pinned = ref.partition("@")
            assert pinned, f"ci.yml: {action} has no pinned ref at all"
            assert _FULL_SHA_RE.match(pinned), f"ci.yml: {action} is pinned to {pinned!r}, not a full commit SHA"

    @pytest.mark.unit
    def test_dependency_audit_step_scans_the_exported_lockfile(self) -> None:
        """The audit must run against the file the export step just produced, not the live environment.

        Auditing ``inputs: .`` (pip-audit's default "resolve from pyproject.toml"
        mode) would re-resolve dependencies at audit time instead of checking the
        exact versions ``uv.lock`` actually pins.
        """
        jobs = _job_blocks(CI_WORKFLOW.read_text())
        security_job = jobs.get("security")
        assert security_job is not None, "ci.yml: expected a 'security' job"

        export_match = re.search(r"^\s*run:\s*uv export[^\n]*-o\s+(\S+)", security_job, re.MULTILINE)
        assert export_match is not None, "ci.yml: could not find the 'uv export ... -o <file>' step"
        exported_file = export_match.group(1)

        audit_index = security_job.index("pip-audit")
        following = security_job[audit_index : audit_index + 400]
        assert exported_file in following, (
            f"ci.yml: the pip-audit step does not reference {exported_file!r}, the file the "
            "'uv export' step produced -- it may be auditing something other than the locked pins"
        )
