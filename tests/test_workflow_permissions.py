"""Regression tests for GitHub Actions permission scoping.

The docs workflow (``docs.yml``) has a ``build`` job that installs and
executes arbitrary third-party dependency code (``uv sync --all-extras --dev``,
then Sphinx and its extensions via ``uv run make docs``) followed by a
separate ``deploy`` job that needs ``pages: write`` and ``id-token: write`` to
publish to GitHub Pages.

Before this fix, those two scopes were declared once, at the *workflow*
level, so GitHub Actions granted them to every job -- including ``build``. A
compromised transitive Sphinx/docs dependency executing during the build job
could have minted an OIDC token and used the ``pages: write`` token to deploy
attacker-controlled content to the project's GitHub Pages site, without ever
touching the ``deploy`` job.

This test parameterizes over every workflow file (not just ``docs.yml``), so
it also guards the general "a job that runs third-party install/build
commands must never hold ``pages``/``id-token`` write access, whether granted
directly or inherited from a workflow-level default" convention against
regressing anywhere else in the repo.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

WORKFLOWS_DIR = Path(__file__).parent.parent / ".github" / "workflows"
WORKFLOW_FILES = sorted(WORKFLOWS_DIR.glob("*.yml"))

# Permission scopes that let a job act outside the checked-out repo (mint an
# OIDC token, publish to GitHub Pages). A job that runs arbitrary third-party
# dependency code must never hold one of these at "write".
_DEPLOY_SCOPES = ("id-token", "pages")

# Heuristic for "this job executes arbitrary third-party code": any step that
# installs dependencies from a lockfile/manifest, or builds the project, can
# run setup.py/build hooks, Sphinx extensions, etc. from packages the repo
# doesn't control.
_INSTALL_RE = re.compile(r"\buv (sync|build)\b|\bpip install\b|\bnpm (install|ci)\b|\bpoetry install\b")

_JOB_HEADER_RE = re.compile(r"^  ([A-Za-z0-9_-]+):[ \t]*$", re.MULTILINE)
_TOP_PERMISSIONS_RE = re.compile(r"^permissions:[ \t]*$", re.MULTILINE)
_JOB_PERMISSIONS_RE = re.compile(r"^ {4}permissions:[ \t]*$", re.MULTILINE)


def _permission_entries(block: str, start: int, indent: int) -> dict[str, str]:
    """Collect ``key: value`` permission entries indented under a ``permissions:`` header.

    ``start`` is the offset of the end of the ``permissions:`` line; entries are
    read until a line with indentation less than or equal to ``indent`` appears.
    """
    entry_re = re.compile(rf"^ {{{indent}}}([a-z-]+):\s*(read|write|none)[ \t]*$")
    entries: dict[str, str] = {}
    for line in block[start:].splitlines():
        if not line.strip():
            continue
        match = entry_re.match(line)
        if not match:
            break
        entries[match.group(1)] = match.group(2)
    return entries


def _top_level_permissions(text: str) -> dict[str, str]:
    """Return the workflow-level ``permissions:`` block, or ``{}`` if absent."""
    jobs_index = text.find("\njobs:")
    header_scope = text if jobs_index == -1 else text[:jobs_index]
    match = _TOP_PERMISSIONS_RE.search(header_scope)
    if not match:
        return {}
    return _permission_entries(header_scope, match.end(), indent=2)


def _job_blocks(text: str) -> dict[str, str]:
    """Split the ``jobs:`` mapping into ``{job_name: block_text}``."""
    jobs_index = text.find("\njobs:")
    if jobs_index == -1:
        return {}
    jobs_text = text[jobs_index + 1 :]
    headers = list(_JOB_HEADER_RE.finditer(jobs_text))
    blocks: dict[str, str] = {}
    for i, header in enumerate(headers):
        end = headers[i + 1].start() if i + 1 < len(headers) else len(jobs_text)
        blocks[header.group(1)] = jobs_text[header.start() : end]
    return blocks


def _job_permissions(block: str) -> dict[str, str]:
    """Return a job's own ``permissions:`` block, or ``{}`` if it declares none."""
    match = _JOB_PERMISSIONS_RE.search(block)
    if not match:
        return {}
    return _permission_entries(block, match.end(), indent=6)


def _runs_third_party_install(block: str) -> bool:
    """Whether the job has a ``run:`` step invoking a dependency install/build command."""
    return bool(_INSTALL_RE.search(block))


def _effective_permissions(job_block: str, top_permissions: dict[str, str]) -> dict[str, str]:
    """A job's own ``permissions:`` fully replaces the workflow default; absent, it inherits it."""
    job_permissions = _job_permissions(job_block)
    return job_permissions if job_permissions else top_permissions


class TestThirdPartyCodeJobsCannotDeploy:
    """A job that executes third-party dependency code must not hold deploy-capable permissions
    it doesn't need, when another job in the same workflow is the one that needs them.

    Before the fix, ``docs.yml`` declared ``pages: write`` and ``id-token: write``
    at the workflow level, so its ``build`` job -- which runs ``uv sync`` and then
    Sphinx -- inherited both, even though only the separate ``deploy`` job uses
    them. This assertion would have failed against that version of the file.

    Single-job workflows (e.g. ``publish.yml``, which needs ``id-token: write``
    in the same job that runs ``uv build`` for PyPI Trusted Publishing) are out
    of scope here: there is no *other* job for the permission to leak into, so
    this isn't the "workflow-level default overshares" class of bug -- splitting
    that into build/publish jobs is a separate, larger change.
    """

    @pytest.mark.unit
    @pytest.mark.parametrize("workflow_path", WORKFLOW_FILES, ids=lambda p: p.name)
    def test_install_jobs_lack_deploy_permissions(self, workflow_path: Path) -> None:
        text = workflow_path.read_text()
        jobs = _job_blocks(text)
        if len(jobs) <= 1:
            pytest.skip(f"{workflow_path.name} has a single job; no other job for permissions to leak into")

        top_permissions = _top_level_permissions(text)

        for job_name, block in jobs.items():
            if not _runs_third_party_install(block):
                continue

            effective = _effective_permissions(block, top_permissions)
            for scope in _DEPLOY_SCOPES:
                assert effective.get(scope) != "write", (
                    f"{workflow_path.name}: job {job_name!r} runs third-party dependency "
                    f"code but has (or inherits) {scope}: write"
                )


class TestDocsWorkflowPermissionsAreJobScoped:
    """``docs.yml`` specifically: build and deploy must each hold only what they need."""

    @pytest.mark.unit
    def test_no_workflow_level_permissions(self) -> None:
        text = (WORKFLOWS_DIR / "docs.yml").read_text()
        assert _top_level_permissions(text) == {}, (
            "docs.yml should scope permissions per-job, not at the workflow level "
            "(the build job would otherwise inherit deploy's Pages/OIDC access)"
        )

    @pytest.mark.unit
    def test_build_job_is_read_only(self) -> None:
        text = (WORKFLOWS_DIR / "docs.yml").read_text()
        build_permissions = _job_permissions(_job_blocks(text)["build"])
        assert build_permissions == {"contents": "read"}

    @pytest.mark.unit
    def test_deploy_job_holds_the_pages_scopes(self) -> None:
        text = (WORKFLOWS_DIR / "docs.yml").read_text()
        deploy_permissions = _job_permissions(_job_blocks(text)["deploy"])
        assert deploy_permissions.get("pages") == "write"
        assert deploy_permissions.get("id-token") == "write"
