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

A follow-up fix hardens this further: the ``ref_type == 'tag'`` half of the
guard assumed a tag protection ruleset and ``pypi`` environment protection
rules would stop a write collaborator from just creating their own tag and
dispatching against it. Neither is actually configured on this repo
(confirmed via the GitHub API: only a branch ruleset exists, and the
``pypi`` environment's ``protection_rules`` is ``[]``), so that assumption
didn't hold -- any write collaborator could still create tag ``v9.9.9``
against an arbitrary commit and manually dispatch to publish it. The fix
adds ``github.event_name == 'workflow_dispatch' && ... &&
github.actor == github.repository_owner`` to the ``workflow_dispatch`` half
of the condition, so a manual dispatch only ever runs for the repo owner,
independent of tag/environment protections. The ``release`` event half is
left unrestricted, since cutting a GitHub Release is the normal, unaffected
release flow.

CAVEAT this fix does *not* close: ``workflow_dispatch`` evaluates the
workflow definition as it exists at the *dispatched ref*, not this file's
current contents on the default branch. A write collaborator can still tag
(or author a new commit reverting to) an older revision of this file that
predates this guard -- e.g. commit ``a70f721``, which already set
``environment: pypi`` and ``id-token: write`` behind a bare, unrestricted
``workflow_dispatch`` -- and dispatch against that ref to bypass this check
entirely. This inline guard is defense-in-depth only; fully closing the
finding requires the ``pypi`` environment's required-reviewers protection
rule (enforced by GitHub at the environment level for *any* workflow
revision that references it, regardless of that revision's own ``if:``
logic) and/or a tag protection ruleset, neither of which a repo-file test
can verify or enforce.
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
        assert (
            "github.event_name == 'release'" in condition
        ), f"publish.yml: 'build' job condition {condition!r} no longer explicitly allows the normal 'release' trigger"

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


def _split_top_level(condition: str, operator: str) -> list[str]:
    """Split a boolean expression on ``operator`` (``'||'`` or ``'&&'``) at parenthesis depth 0.

    ``github.event_name == 'release' || (github.ref_type == 'tag' && ...)``
    must split into its two top-level ``||`` alternatives without also
    splitting on any ``||``/``&&`` nested inside the parenthesized group --
    and, symmetrically, splitting the inside of that group on ``&&`` must
    not be fooled by a stray ``||`` slipped in among the conjuncts.
    """
    parts: list[str] = []
    depth = 0
    current = ""
    i = 0
    while i < len(condition):
        if condition[i] == "(":
            depth += 1
            current += condition[i]
        elif condition[i] == ")":
            depth -= 1
            current += condition[i]
        elif depth == 0 and condition[i : i + 2] == operator:
            parts.append(current.strip())
            current = ""
            i += 1
        else:
            current += condition[i]
        i += 1
    parts.append(current.strip())
    return parts


def _split_top_level_or(condition: str) -> list[str]:
    return _split_top_level(condition, "||")


#: The exact set of conjuncts required in the workflow_dispatch alternative.
#: Checked as an unordered set of *conjuncts* (split on top-level ``&&``)
#: rather than substrings, so an expression that OR's the actor check in
#: instead of AND-ing it (e.g. ``ref_type == 'tag' || actor == ...``) --
#: which would satisfy naive substring checks but not actually restrict
#: anything -- is rejected.
_REQUIRED_WORKFLOW_DISPATCH_CONJUNCTS = frozenset(
    {
        "github.event_name == 'workflow_dispatch'",
        "github.ref_type == 'tag'",
        "github.actor == github.repository_owner",
    }
)


class TestWorkflowDispatchIsRestrictedToTheRepoOwner:
    """A manual ``workflow_dispatch`` run must not be triggerable by just any write collaborator.

    The ``ref_type == 'tag'`` guard alone assumed a tag protection ruleset and
    ``pypi`` environment protection rules would stop a write collaborator from
    creating their own tag and dispatching against it. Neither is configured
    on this repo, so the guard by itself doesn't close the gap described in
    ``TestWorkflowDispatchIsRestrictedToTagRefs``. This class checks the
    additional ``github.actor == github.repository_owner`` restriction on the
    ``workflow_dispatch`` alternative specifically.
    """

    @pytest.mark.unit
    def test_workflow_dispatch_alternative_requires_repo_owner_actor(self) -> None:
        jobs = _job_blocks(PUBLISH_WORKFLOW.read_text())
        build_job = jobs.get("build")
        assert build_job is not None, "publish.yml: expected a 'build' job"

        match = _IF_RE.search(build_job)
        assert match is not None, "publish.yml: the 'build' job has no 'if:' condition"
        condition = match.group(1)

        alternatives = _split_top_level_or(condition)
        tag_alternative = next((alt for alt in alternatives if "github.ref_type == 'tag'" in alt), None)
        assert tag_alternative is not None, (
            f"publish.yml: 'build' job condition {condition!r} has no top-level "
            "alternative gating on 'github.ref_type == \\'tag\\''"
        )

        # Strip one layer of enclosing parens, if present, before splitting on '&&'.
        stripped = tag_alternative.strip()
        if stripped.startswith("(") and stripped.endswith(")"):
            stripped = stripped[1:-1].strip()
        conjuncts = {part.strip() for part in _split_top_level(stripped, "&&")}

        assert conjuncts == _REQUIRED_WORKFLOW_DISPATCH_CONJUNCTS, (
            f"publish.yml: the workflow_dispatch alternative {tag_alternative!r} must AND "
            f"together exactly {sorted(_REQUIRED_WORKFLOW_DISPATCH_CONJUNCTS)!r} -- got "
            f"{sorted(conjuncts)!r}. Combining the actor/ref checks with '||' instead of "
            "'&&' (or dropping one) would let any write collaborator satisfy this "
            "alternative without actually being the repo owner, since the tag-ref guard "
            "alone depends on a tag protection ruleset and 'pypi' environment protection "
            "rules that aren't configured on this repo"
        )

    @pytest.mark.unit
    def test_release_alternative_is_not_restricted_to_repo_owner(self) -> None:
        """The normal ``release: published`` flow must stay unaffected by the actor check."""
        jobs = _job_blocks(PUBLISH_WORKFLOW.read_text())
        build_job = jobs.get("build")
        assert build_job is not None, "publish.yml: expected a 'build' job"

        match = _IF_RE.search(build_job)
        assert match is not None, "publish.yml: the 'build' job has no 'if:' condition"
        condition = match.group(1)

        alternatives = _split_top_level_or(condition)
        release_alternative = next((alt for alt in alternatives if "github.event_name == 'release'" in alt), None)
        assert release_alternative is not None, (
            f"publish.yml: 'build' job condition {condition!r} has no top-level "
            "alternative allowing the normal 'release' trigger"
        )
        assert release_alternative.strip() == "github.event_name == 'release'", (
            f"publish.yml: the 'release' alternative {release_alternative!r} must be exactly "
            "\"github.event_name == 'release'\" with nothing AND-ed or OR-ed in -- cutting a "
            "GitHub Release is the normal release flow and must remain available to any "
            "write collaborator, unrestricted"
        )
