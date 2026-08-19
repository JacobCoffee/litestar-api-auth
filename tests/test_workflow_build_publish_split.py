"""Regression tests for the ``publish.yml`` build/publish job split.

Before this fix, ``publish.yml`` was a single job that held
``id-token: write`` (to mint the OIDC token PyPI's Trusted Publishing trusts
for this repo) *and* ran ``uv build`` in that same job, via ``astral-sh/setup-uv``
with no ``version:`` input pinning which ``uv`` release got installed. ``uv
build`` resolves the ``uv_build`` PEP 517 backend fresh, outside ``uv.lock``,
with no exact version pin. A compromised release of ``uv`` or ``uv_build``
pulled in at publish time would have run arbitrary build-backend code inside
the privileged job, able to steal the OIDC token or ship a backdoored wheel to
PyPI.

The fix splits the workflow into a ``build`` job (no ``id-token``, builds the
package with a pinned ``uv`` version) that uploads the built distributions as
an artifact, and a ``publish-release`` job (``id-token: write``) that only
downloads that artifact and hands it to ``pypa/gh-action-pypi-publish`` --
it never executes build-toolchain code itself. Each assertion below documents
the specific line(s) it would have failed against in the pre-fix file.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
PUBLISH_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "publish.yml"
PYPROJECT = REPO_ROOT / "pyproject.toml"

_JOB_HEADER_RE = re.compile(r"^  ([A-Za-z0-9_-]+):[ \t]*$", re.MULTILINE)
_USES_RE = re.compile(r"^\s*(?:-\s+)?uses:\s*([^\s#]+)", re.MULTILINE)
_RUN_RE = re.compile(r"^\s*run:", re.MULTILINE)
_NEEDS_RE = re.compile(r"^\s*needs:\s*(.+?)\s*$", re.MULTILINE)
_PERMISSIONS_BLOCK_RE = re.compile(r"^ {4}permissions:\n((?: {6}[a-z-]+:\s*[a-z-]+\n?)+)", re.MULTILINE)


def _job_blocks(text: str) -> dict[str, str]:
    """Split the ``jobs:`` mapping into ``{job_name: block_text}``."""
    jobs_index = text.find("\njobs:")
    assert jobs_index != -1, "publish.yml has no 'jobs:' key"
    jobs_text = text[jobs_index + 1 :]
    headers = list(_JOB_HEADER_RE.finditer(jobs_text))
    blocks: dict[str, str] = {}
    for i, header in enumerate(headers):
        end = headers[i + 1].start() if i + 1 < len(headers) else len(jobs_text)
        blocks[header.group(1)] = jobs_text[header.start() : end]
    return blocks


def _uses_actions(block: str) -> list[str]:
    """Return the ``uses:`` action names (without the ``@ref`` suffix) referenced in a job block."""
    return [ref.partition("@")[0] for ref in _USES_RE.findall(block)]


def _permissions(block: str) -> dict[str, str]:
    """Return a job block's own ``permissions:`` entries as ``{scope: level}``."""
    match = _PERMISSIONS_BLOCK_RE.search(block)
    assert match, "expected a 4-space-indented 'permissions:' block with 6-space-indented entries"
    return dict(line.strip().split(": ") for line in match.group(1).splitlines() if line.strip())


class TestPublishWorkflowSplitsBuildFromPublish:
    """The privileged, ``id-token: write`` job must never itself build the package."""

    @pytest.mark.unit
    def test_publish_workflow_has_a_separate_build_job(self) -> None:
        jobs = _job_blocks(PUBLISH_WORKFLOW.read_text())
        assert len(jobs) >= 2, (
            "publish.yml has a single job: uv build ran in the same job that holds "
            "id-token: write, so a compromised build-toolchain release runs with "
            "access to the PyPI Trusted Publishing OIDC token"
        )

    @pytest.mark.unit
    def test_id_token_job_does_not_run_uv_build(self) -> None:
        jobs = _job_blocks(PUBLISH_WORKFLOW.read_text())
        for job_name, block in jobs.items():
            if "id-token: write" not in block:
                continue
            assert "uv build" not in block, (
                f"publish.yml: job {job_name!r} holds id-token: write but also runs "
                "'uv build' itself, so a compromised uv/uv_build release would run "
                "inside the job that holds the PyPI OIDC token"
            )

    @pytest.mark.unit
    def test_id_token_job_only_downloads_and_publishes_a_prebuilt_artifact(self) -> None:
        """The ``id-token: write`` job must be incapable of running arbitrary code at all.

        It's not enough that this job merely lacks a literal ``uv build`` string --
        it must have no ``run:`` step of any kind, must depend on (``needs:``) the
        ``build`` job so the artifact always exists first, must hold exactly the
        ``id-token: write`` permission and no other write scope, and its only
        ``uses:`` steps must be the pinned download-artifact and PyPI-publish
        actions -- nothing that could itself execute untrusted code.
        """
        jobs = _job_blocks(PUBLISH_WORKFLOW.read_text())
        publish_jobs = {name: block for name, block in jobs.items() if "id-token: write" in block}
        assert publish_jobs, "publish.yml: no job holds id-token: write"

        for job_name, block in publish_jobs.items():
            needs_match = _NEEDS_RE.search(block)
            assert needs_match is not None, f"publish.yml: job {job_name!r} holds id-token: write but has no 'needs:'"
            assert needs_match.group(1) == "build", (
                f"publish.yml: job {job_name!r} holds id-token: write but does not "
                "declare 'needs: build', so it isn't guaranteed to run after (and "
                "consume the artifact from) the build job"
            )

            assert _permissions(block) == {
                "id-token": "write"
            }, f"publish.yml: job {job_name!r} must hold exactly {{'id-token': 'write'}} and no other permission scope"

            assert not _RUN_RE.search(block), (
                f"publish.yml: job {job_name!r} holds id-token: write but has a 'run:' "
                "step, so it could execute arbitrary shell commands with access to the "
                "PyPI OIDC token instead of only downloading a prebuilt artifact"
            )

            assert _uses_actions(block) == ["actions/download-artifact", "pypa/gh-action-pypi-publish"], (
                f"publish.yml: job {job_name!r} must use only download-artifact (to fetch "
                "the build job's output) and gh-action-pypi-publish -- any other action "
                "would run inside the job that holds the PyPI OIDC token"
            )

    @pytest.mark.unit
    def test_build_job_lacks_id_token_permission(self) -> None:
        jobs = _job_blocks(PUBLISH_WORKFLOW.read_text())
        build_job = jobs.get("build")
        assert build_job is not None, "publish.yml: expected a 'build' job"
        assert (
            "id-token" not in build_job
        ), "publish.yml: the 'build' job -- which runs 'uv build' -- must not hold any id-token permission"
        assert "uv build" in build_job, "publish.yml: 'build' job no longer builds the package"


class TestSetupUvVersionIsPinned:
    """``astral-sh/setup-uv`` must install a specific, known ``uv`` release, not whatever is latest.

    Before this fix, the ``Install uv`` step had no ``version:`` input, so
    ``setup-uv`` installed the latest ``uv`` release available at run time.
    This assertion would have failed against that version of the file.
    """

    @pytest.mark.unit
    def test_install_uv_step_pins_a_version(self) -> None:
        text = PUBLISH_WORKFLOW.read_text()
        setup_uv_index = text.index("astral-sh/setup-uv@")
        # The `with:` block for this step; bounded loosely by the next step or job.
        following = text[setup_uv_index : setup_uv_index + 400]
        assert re.search(r'version:\s*"[0-9]+\.[0-9]+\.[0-9]+"', following), (
            "publish.yml: the 'Install uv' step does not pin an explicit uv 'version:', "
            "so it installs whatever uv release is latest at publish time"
        )


class TestBuildBackendVersionIsPinned:
    """``uv_build`` (the PEP 517 backend used by ``uv build``) must be pinned to an exact version.

    Before this fix, ``pyproject.toml`` constrained it to a range
    (``uv_build>=0.9.11,<0.11.0``), so any release in that window -- including
    one published after this repo was last reviewed -- could be resolved fresh
    at publish time, outside ``uv.lock``. This assertion would have failed
    against that version of the file.
    """

    @pytest.mark.unit
    def test_uv_build_requirement_is_an_exact_pin(self) -> None:
        text = PYPROJECT.read_text()
        match = re.search(r'requires\s*=\s*\[\s*"(uv_build[^"]*)"\s*\]', text)
        assert match, "pyproject.toml: could not find the [build-system] 'requires' entry"
        requirement = match.group(1)
        assert re.fullmatch(r"uv_build==[0-9]+\.[0-9]+\.[0-9]+", requirement), (
            f"pyproject.toml: build-system requires {requirement!r}, not an exact "
            "'uv_build==X.Y.Z' pin, so the build backend can still float within a range"
        )
