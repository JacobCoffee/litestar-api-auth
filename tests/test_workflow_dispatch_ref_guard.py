"""Regression test for the ``publish.yml`` ``workflow_dispatch`` ref guard.

Before this fix, ``publish.yml`` declared a bare ``workflow_dispatch:``
trigger with no restriction on which ref it runs against, and neither job
had any ``if:`` condition. Any collaborator with write access to the repo
could manually dispatch this workflow against an arbitrary branch or
commit -- not just a released tag -- and have it built and published to
PyPI under Trusted Publishing, entirely outside the normal tagged-release
flow. Whether that succeeded came down to protections on the ``pypi``
environment alone (required reviewers, branch/tag restrictions), which
aren't verifiable from the repo and may not be configured.

The fix adds an ``if: github.event_name == 'release' || github.ref_type ==
'tag'`` guard to the ``build`` job. Manual dispatch against a branch (the
default selection in the GitHub UI) now runs zero steps, and because
``publish-release`` has ``needs: build``, it is skipped too -- publishing
only ever happens for a tag ref (whether via the ``release`` event or a
manual dispatch explicitly targeting an existing tag), which combined with
a tag protection ruleset closes the arbitrary-ref gap. This assertion would
have failed against the pre-fix file, which had no ``if:`` key on the
``build`` job at all.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
PUBLISH_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "publish.yml"

_JOB_HEADER_RE = re.compile(r"^  ([A-Za-z0-9_-]+):[ \t]*$", re.MULTILINE)
_IF_RE = re.compile(r"^\s*if:\s*(.+?)\s*$", re.MULTILINE)


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


class TestWorkflowDispatchIsRestrictedToTagRefs:
    """Manual ``workflow_dispatch`` runs must not be able to publish an arbitrary ref."""

    @pytest.mark.unit
    def test_publish_workflow_has_bare_workflow_dispatch_trigger(self) -> None:
        """Sanity check that the scenario this test guards against still applies.

        If ``workflow_dispatch`` ever grows its own ref restriction (unlike
        ``push``/``pull_request``, it doesn't support a ``branches:`` filter
        today) or is removed, this test should be revisited rather than
        silently passing for the wrong reason.
        """
        text = PUBLISH_WORKFLOW.read_text()
        on_block = text[text.index("\non:") : text.index("\njobs:")]
        assert re.search(r"^  workflow_dispatch:\s*$", on_block, re.MULTILINE), (
            "publish.yml: expected a bare 'workflow_dispatch:' trigger; if this changed, "
            "re-evaluate whether the ref guard on the 'build' job is still needed"
        )

    @pytest.mark.unit
    def test_build_job_is_gated_to_release_or_tag_refs(self) -> None:
        jobs = _job_blocks(PUBLISH_WORKFLOW.read_text())
        build_job = jobs.get("build")
        assert build_job is not None, "publish.yml: expected a 'build' job"

        match = _IF_RE.search(build_job)
        assert match is not None, (
            "publish.yml: the 'build' job has no 'if:' condition, so a manual "
            "'workflow_dispatch' run against an arbitrary branch or commit would "
            "build and (via the downstream 'publish-release' job) publish it to "
            "PyPI outside the normal tagged-release flow"
        )

        condition = match.group(1)
        assert "github.ref_type == 'tag'" in condition, (
            f"publish.yml: 'build' job condition {condition!r} does not restrict "
            "workflow_dispatch runs to tag refs, so it could still run against an "
            "arbitrary branch"
        )
        assert "github.event_name == 'release'" in condition, (
            f"publish.yml: 'build' job condition {condition!r} no longer explicitly allows the normal 'release' trigger"
        )

    @pytest.mark.unit
    def test_publish_release_job_depends_on_build_with_no_override(self) -> None:
        """``publish-release`` must inherit the guard via ``needs: build``, not bypass it.

        GitHub Actions skips a job when the job it ``needs:`` was skipped,
        *unless* that job's own ``if:`` overrides the implicit ``success()``
        default (e.g. with ``always()``). If ``publish-release`` ever grew
        such an override, a skipped ``build`` would no longer stop it from
        running.
        """
        jobs = _job_blocks(PUBLISH_WORKFLOW.read_text())
        publish_job = jobs.get("publish-release")
        assert publish_job is not None, "publish.yml: expected a 'publish-release' job"

        needs_match = re.search(r"^\s*needs:\s*(.+?)\s*$", publish_job, re.MULTILINE)
        assert needs_match is not None, "publish.yml: 'publish-release' has no 'needs:' key"
        assert needs_match.group(1) == "build", (
            "publish.yml: 'publish-release' must declare 'needs: build' so a "
            "skipped build job (untagged workflow_dispatch run) also skips publishing"
        )

        if_match = _IF_RE.search(publish_job)
        assert if_match is None or "always()" not in if_match.group(1), (
            "publish.yml: 'publish-release' has an 'if:' condition that could run "
            "even when 'build' was skipped, bypassing the tag-ref guard"
        )
