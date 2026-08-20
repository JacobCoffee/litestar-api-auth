"""Regression test for CI's missing dependency vulnerability audit.

Before this fix, ``ci.yml``'s ``security`` job ran only ``zizmor`` --  a
GitHub Actions *workflow* linter. It never inspected the project's own
dependencies, so a newly published advisory against an already-locked
package (e.g. a CVE landing against a pinned ``litestar`` or ``multipart``
release well after ``uv.lock`` was generated) would never surface in CI. A
vulnerable pin could sit in ``uv.lock`` indefinitely, undetected, until
someone happened to run an audit tool by hand.

The fix adds a dedicated ``dependency-audit`` job that exports the locked
dependency set from ``uv.lock`` to a requirements-style file (so the audit
covers exactly what would actually be installed, not whatever
``pyproject.toml`` alone would re-resolve to) and runs
``pypa/gh-action-pip-audit`` against that export. ``uv.lock`` is a universal
lock containing ``python_full_version``-conditioned pins (e.g. ``sphinx``
resolves differently below/above Python 3.11); pip-audit evaluates those
markers against whichever interpreter it runs under, so the job matrixes
over one Python version below and one at/above that split to make sure both
pinned branches actually get scanned, not just whichever one happens to
match a single runner's default interpreter.

This test would have failed against the pre-fix file, which had no
``dependency-audit`` job, no ``uv export`` step, and no ``pip-audit``
reference anywhere in ``ci.yml``.
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


class TestSecurityJobUnaffected:
    """The pre-existing ``security`` job must keep running zizmor, unmodified by this fix."""

    @pytest.mark.unit
    def test_security_job_still_runs_only_zizmor(self) -> None:
        """Only the job's own steps must stay zizmor-only.

        ``_job_blocks`` slices up to (not including) the *next* job's header,
        so this deliberately checks the job's ``uses:``/``run:`` steps rather
        than a blunt substring search over the whole block -- the latter would
        also match ``dependency-audit``'s section-comment banner, which trails
        immediately after ``security``'s last step in the raw file.
        """
        jobs = _job_blocks(CI_WORKFLOW.read_text())
        security_job = jobs.get("security")
        assert security_job is not None, "ci.yml: expected a 'security' job"
        assert "zizmorcore/zizmor-action" in security_job, "ci.yml: 'security' job no longer runs zizmor"

        refs = _uses_refs(security_job)
        assert not any("pip-audit" in ref.partition("@")[0] for ref in refs), (
            "ci.yml: 'security' job now has a pip-audit 'uses:' step -- the dependency "
            "audit belongs in its own 'dependency-audit' job (see TestDependencyAuditJob), "
            "not bolted onto the workflow-linter job"
        )
        assert not re.search(r"^\s*run:\s*.*pip-audit", security_job, re.MULTILINE), (
            "ci.yml: 'security' job now has a 'run:' step invoking pip-audit -- it "
            "belongs in its own 'dependency-audit' job instead"
        )


class TestDependencyAuditJob:
    """A dedicated job must scan locked dependencies for known vulnerabilities."""

    @pytest.mark.unit
    def test_dependency_audit_job_exists(self) -> None:
        jobs = _job_blocks(CI_WORKFLOW.read_text())
        assert "dependency-audit" in jobs, (
            "ci.yml: no 'dependency-audit' job, so advisories against already-locked dependencies never surface in CI"
        )

    @pytest.mark.unit
    def test_exports_the_locked_dependency_set(self) -> None:
        jobs = _job_blocks(CI_WORKFLOW.read_text())
        job = jobs.get("dependency-audit")
        assert job is not None, "ci.yml: expected a 'dependency-audit' job"

        export_match = re.search(r"^\s*run:\s*(uv export[^\n]*)$", job, re.MULTILINE)
        assert export_match is not None, (
            "ci.yml: 'dependency-audit' job has no 'uv export' step, so there is "
            "nothing for a dependency-audit tool to scan that reflects the actual locked pins"
        )
        command = export_match.group(1)
        assert "--locked" in command.split(), (
            f"ci.yml: {command!r} does not pass --locked, so the export could silently "
            "diverge from uv.lock instead of failing when the lockfile is stale"
        )

    @pytest.mark.unit
    def test_runs_a_pinned_pip_audit_step(self) -> None:
        jobs = _job_blocks(CI_WORKFLOW.read_text())
        job = jobs.get("dependency-audit")
        assert job is not None, "ci.yml: expected a 'dependency-audit' job"

        refs = _uses_refs(job)
        audit_refs = [ref for ref in refs if "pip-audit" in ref.partition("@")[0]]
        assert audit_refs, "ci.yml: 'dependency-audit' job has no pip-audit (or equivalent) step"

        for ref in audit_refs:
            action, _, pinned = ref.partition("@")
            assert pinned, f"ci.yml: {action} has no pinned ref at all"
            assert _FULL_SHA_RE.match(pinned), f"ci.yml: {action} is pinned to {pinned!r}, not a full commit SHA"

    @pytest.mark.unit
    def test_pip_audit_step_has_no_failure_suppressing_input(self) -> None:
        """The pip-audit step's own ``with:`` block must not turn it into a non-enforcing check.

        ``continue-on-error: true`` (a generic GitHub Actions step key) or
        ``internal-be-careful-allow-failure: true`` (a gh-action-pip-audit
        input) would each let the job succeed even when pip-audit finds a
        vulnerability, silently reintroducing the exact gap this fix closes.
        """
        jobs = _job_blocks(CI_WORKFLOW.read_text())
        job = jobs.get("dependency-audit")
        assert job is not None, "ci.yml: expected a 'dependency-audit' job"

        audit_index = job.index("pip-audit")
        step_text = job[audit_index : audit_index + 400]
        assert "continue-on-error" not in step_text, (
            "ci.yml: the pip-audit step sets 'continue-on-error', so the job would "
            "still succeed even when a vulnerability is found"
        )
        assert "allow-failure" not in step_text, (
            "ci.yml: the pip-audit step sets an 'allow-failure' input, so it would "
            "still succeed even when a vulnerability is found"
        )

    @pytest.mark.unit
    def test_audit_step_scans_the_exported_lockfile(self) -> None:
        """The audit must run against the file the export step just produced, not the live environment.

        Auditing ``inputs: .`` (pip-audit's default "resolve from pyproject.toml"
        mode) would re-resolve dependencies at audit time instead of checking the
        exact versions ``uv.lock`` actually pins.
        """
        jobs = _job_blocks(CI_WORKFLOW.read_text())
        job = jobs.get("dependency-audit")
        assert job is not None, "ci.yml: expected a 'dependency-audit' job"

        export_match = re.search(r"^\s*run:\s*uv export[^\n]*-o\s+(\S+)", job, re.MULTILINE)
        assert export_match is not None, "ci.yml: could not find the 'uv export ... -o <file>' step"
        exported_file = export_match.group(1)

        # Anchor on the actual `uses:` invocation, not a bare "pip-audit" substring --
        # a preceding step (or comment) that mentions pip-audit while pinning its exact
        # version would otherwise shift this window away from the action's own `with:` block.
        audit_uses_match = re.search(r"^\s*(?:-\s+)?uses:\s*\S*pip-audit\S*", job, re.MULTILINE)
        assert audit_uses_match is not None, "ci.yml: could not find a 'uses:' step referencing pip-audit"
        audit_index = audit_uses_match.start()
        following = job[audit_index : audit_index + 400]
        assert exported_file in following, (
            f"ci.yml: the pip-audit step does not reference {exported_file!r}, the file the "
            "'uv export' step produced -- it may be auditing something other than the locked pins"
        )

    @pytest.mark.unit
    def test_matrix_covers_both_sides_of_uv_lock_s_python_marker_split(self) -> None:
        """``uv.lock`` pins some packages differently below/above Python 3.11 (see ``sphinx``).

        pip-audit resolves ``python_full_version`` markers against whichever
        interpreter it runs under, so auditing under only one Python version
        would silently skip whichever pinned branch doesn't match it. The job
        must matrix over at least one version below 3.11 and one at/above it.
        """
        jobs = _job_blocks(CI_WORKFLOW.read_text())
        job = jobs.get("dependency-audit")
        assert job is not None, "ci.yml: expected a 'dependency-audit' job"

        matrix_match = re.search(r"python-version:\s*\[([^\]]+)\]", job)
        assert matrix_match is not None, (
            "ci.yml: 'dependency-audit' job has no 'python-version' matrix, so it only "
            "ever audits under a single interpreter -- silently skipping whichever side "
            "of uv.lock's python_full_version marker split doesn't match it"
        )
        versions = [v.strip().strip("\"'") for v in matrix_match.group(1).split(",")]

        def _as_tuple(v: str) -> tuple[int, int]:
            major, _, minor = v.partition(".")
            return int(major), int(minor)

        assert any(_as_tuple(v) < (3, 11) for v in versions), (
            f"ci.yml: 'dependency-audit' python-version matrix {versions!r} has nothing "
            "below Python 3.11, so the pre-3.11 side of uv.lock's marker split (e.g. the "
            "older sphinx pin) never gets audited"
        )
        assert any(_as_tuple(v) >= (3, 11) for v in versions), (
            f"ci.yml: 'dependency-audit' python-version matrix {versions!r} has nothing "
            "at or above Python 3.11, so the post-3.11 side of uv.lock's marker split "
            "never gets audited"
        )

    @pytest.mark.unit
    def test_setup_python_step_is_wired_to_the_matrix(self) -> None:
        """The matrix is worthless if 'Set up Python' doesn't actually consume it.

        Without ``python-version: ${{ matrix.python-version }}`` on a
        ``setup-python`` step, every matrix leg would still run pip-audit under
        whatever Python the runner ships by default -- auditing the same single
        marker branch twice instead of both branches.
        """
        jobs = _job_blocks(CI_WORKFLOW.read_text())
        job = jobs.get("dependency-audit")
        assert job is not None, "ci.yml: expected a 'dependency-audit' job"

        assert "actions/setup-python" in job, "ci.yml: 'dependency-audit' job has no 'actions/setup-python' step"
        setup_python_index = job.index("actions/setup-python")
        following = job[setup_python_index : setup_python_index + 200]
        assert "matrix.python-version" in following, (
            "ci.yml: 'dependency-audit' job's 'actions/setup-python' step does not "
            "reference '${{ matrix.python-version }}', so the python-version matrix "
            "doesn't actually control which interpreter pip-audit runs under"
        )

    @pytest.mark.unit
    def test_ci_success_gate_depends_on_dependency_audit(self) -> None:
        text = CI_WORKFLOW.read_text()
        jobs = _job_blocks(text)
        gate = jobs.get("ci-success")
        assert gate is not None, "ci.yml: expected a 'ci-success' job"

        needs_match = re.search(r"^\s*needs:\s*\[([^\]]+)\]", gate, re.MULTILINE)
        assert needs_match is not None, "ci.yml: 'ci-success' has no 'needs:' list"
        needs = [n.strip() for n in needs_match.group(1).split(",")]
        assert "dependency-audit" in needs, (
            "ci.yml: 'ci-success' does not depend on 'dependency-audit', so a failing "
            "dependency audit would not block the branch-protection gate"
        )
        assert "needs.dependency-audit.result" in gate, (
            "ci.yml: 'ci-success' depends on 'dependency-audit' but never checks its "
            "result, so a failing audit would still report 'CI passed!'"
        )
