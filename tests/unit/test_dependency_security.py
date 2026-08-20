"""Regression tests for known-vulnerable transitive dependency versions.

These tests guard against re-introducing dependency versions with known
security advisories via a stale or downgraded lock file.
"""

from __future__ import annotations

import importlib.metadata
import sys
from pathlib import Path

import pytest
from packaging.requirements import Requirement
from packaging.version import Version

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

_LOCK_FILE = Path(__file__).parents[2] / "uv.lock"

_URLLIB3_MIN_VERSION = Version("2.7.0")
"""Versions below this are vulnerable to:

- GHSA-mf9v-mfxr-j63j: decompression-bomb DoS via the streaming API
  (affects urllib3 >=2.6.0,<2.7.0).
- GHSA-qccp-gfcp-xxvc: Authorization/Cookie header leak on cross-origin
  redirects via the low-level ProxyManager API (affects urllib3
  >=1.23,<2.7.0).

Both are fixed in urllib3 2.7.0.
"""


def test_uv_lock_pins_urllib3_above_vulnerable_versions() -> None:
    """uv.lock must not pin a urllib3 affected by GHSA-mf9v-mfxr-j63j /
    GHSA-qccp-gfcp-xxvc.

    urllib3 is pulled in transitively via sphinx -> requests in the docs
    dependency group, so this reads the lock file directly rather than the
    currently-installed environment: it catches a regression even if the
    local `.venv` happens to be out of sync with `uv.lock`.
    """
    lock_data = tomllib.loads(_LOCK_FILE.read_text())
    urllib3_entries = [pkg for pkg in lock_data["package"] if pkg["name"] == "urllib3"]

    assert urllib3_entries, "urllib3 not found in uv.lock; expected it as a transitive dependency"

    for entry in urllib3_entries:
        locked_version = Version(entry["version"])
        assert locked_version >= _URLLIB3_MIN_VERSION, (
            f"uv.lock pins urllib3 {locked_version}, which is vulnerable to "
            "GHSA-mf9v-mfxr-j63j and/or GHSA-qccp-gfcp-xxvc; run "
            "`uv lock --upgrade-package urllib3` to update it."
        )


def test_installed_urllib3_above_vulnerable_versions() -> None:
    """The synced environment must match the lock file's fixed urllib3.

    Complements the uv.lock check above by catching an environment that
    drifted from the lock file (e.g. `.venv` synced before the lock was
    upgraded).
    """
    try:
        installed_version = Version(importlib.metadata.version("urllib3"))
    except importlib.metadata.PackageNotFoundError:
        pytest.skip("urllib3 not installed (docs dependency group not synced)")

    assert installed_version >= _URLLIB3_MIN_VERSION, (
        f"urllib3 {installed_version} is vulnerable to GHSA-mf9v-mfxr-j63j "
        "and/or GHSA-qccp-gfcp-xxvc; run `uv sync` to match the updated lock file."
    )


_PYPROJECT_FILE = Path(__file__).parents[2] / "pyproject.toml"

_LITESTAR_MIN_VERSION = Version("2.22.0")
"""Versions below this are vulnerable to:

- PYSEC-2026-2195, PYSEC-2026-2196, PYSEC-2026-2197 (fixed in 2.20.0)
- PYSEC-2026-2603, PYSEC-2026-2604 (fixed in 2.22.0)

litestar is this library's sole runtime dependency, so a vulnerable locked
version or an unbounded ``pyproject.toml`` floor both let downstream
resolvers keep an affected release installed.
"""


def test_uv_lock_pins_litestar_above_vulnerable_versions() -> None:
    """uv.lock must not pin a litestar affected by the advisories above.

    Before this fix, uv.lock pinned litestar 2.18.0, which is vulnerable to
    all five advisories; this assertion would have failed against that lock
    file.
    """
    lock_data = tomllib.loads(_LOCK_FILE.read_text())
    litestar_entries = [pkg for pkg in lock_data["package"] if pkg["name"] == "litestar"]

    assert litestar_entries, "litestar not found in uv.lock"

    for entry in litestar_entries:
        locked_version = Version(entry["version"])
        assert locked_version >= _LITESTAR_MIN_VERSION, (
            f"uv.lock pins litestar {locked_version}, which is vulnerable to "
            "PYSEC-2026-2195/2196/2197/2603/2604; run "
            "`uv lock --upgrade-package litestar` to update it."
        )


def test_installed_litestar_above_vulnerable_versions() -> None:
    """The synced environment must match the lock file's fixed litestar.

    Complements the uv.lock check above by catching an environment that
    drifted from the lock file (e.g. `.venv` synced before the lock was
    upgraded).
    """
    try:
        installed_version = Version(importlib.metadata.version("litestar"))
    except importlib.metadata.PackageNotFoundError:
        pytest.skip("litestar not installed")

    assert installed_version >= _LITESTAR_MIN_VERSION, (
        f"litestar {installed_version} is vulnerable to "
        "PYSEC-2026-2195/2196/2197/2603/2604; run `uv sync` to match the updated lock file."
    )


def test_pyproject_litestar_floor_excludes_vulnerable_versions() -> None:
    """``pyproject.toml``'s ``litestar`` floor must exclude the vulnerable range.

    Before this fix, the floor was ``litestar>=2.0``, which lets a downstream
    resolver with an existing constraint or lock in the 2.0-2.21 range install
    a vulnerable litestar even though this library's own metadata declares it
    acceptable. This assertion would have failed against that floor.
    """
    pyproject_data = tomllib.loads(_PYPROJECT_FILE.read_text())
    requirements = [Requirement(dep) for dep in pyproject_data["project"]["dependencies"]]
    litestar_req = next((req for req in requirements if req.name == "litestar"), None)

    assert litestar_req is not None, "litestar not found in [project.dependencies]"

    lower_bounds = [spec.version for spec in litestar_req.specifier if spec.operator in (">=", ">", "==", "~=")]
    assert lower_bounds, f"litestar requirement {litestar_req!r} has no lower-bound specifier"
    assert all(Version(bound) >= _LITESTAR_MIN_VERSION for bound in lower_bounds), (
        f"pyproject.toml's litestar requirement is {litestar_req!r}, which still permits "
        "versions vulnerable to PYSEC-2026-2195/2196/2197/2603/2604"
    )


_MULTIPART_MIN_VERSION = Version("1.3.1")
"""Versions below this are vulnerable to:

- PYSEC-2026-2670: ReDoS (catastrophic backtracking) via crafted multipart
  form bodies, fixed in 1.3.1.

multipart is pulled in transitively via litestar's own multipart form
handling, and litestar>=2.22.0 still allows ``multipart>=1.2.0``, so bumping
litestar's floor alone does not exclude the vulnerable release; a lock file
or downstream resolver could still land on 1.3.0.
"""


def test_uv_lock_pins_multipart_above_vulnerable_versions() -> None:
    """uv.lock must not pin a multipart affected by PYSEC-2026-2670.

    Before this fix, uv.lock pinned multipart 1.3.0, which is vulnerable;
    this assertion would have failed against that lock file.
    """
    lock_data = tomllib.loads(_LOCK_FILE.read_text())
    multipart_entries = [pkg for pkg in lock_data["package"] if pkg["name"] == "multipart"]

    assert multipart_entries, "multipart not found in uv.lock; expected it as a transitive dependency"

    for entry in multipart_entries:
        locked_version = Version(entry["version"])
        assert locked_version >= _MULTIPART_MIN_VERSION, (
            f"uv.lock pins multipart {locked_version}, which is vulnerable to "
            "PYSEC-2026-2670; run `uv lock --upgrade-package multipart` to update it."
        )


def test_installed_multipart_above_vulnerable_versions() -> None:
    """The synced environment must match the lock file's fixed multipart.

    Complements the uv.lock check above by catching an environment that
    drifted from the lock file (e.g. `.venv` synced before the lock was
    upgraded).
    """
    try:
        installed_version = Version(importlib.metadata.version("multipart"))
    except importlib.metadata.PackageNotFoundError:
        pytest.skip("multipart not installed")

    assert installed_version >= _MULTIPART_MIN_VERSION, (
        f"multipart {installed_version} is vulnerable to PYSEC-2026-2670; run `uv sync` to match the updated lock file."
    )


_TRANSITIVE_MIN_VERSIONS = {
    "starlette": (
        Version("1.3.1"),
        "PYSEC-2026-249",
        "sphinx-autobuild in the docs dependency group",
    ),
    "requests": (
        Version("2.33.0"),
        "PYSEC-2026-2275 (also PYSEC-2026-1872, PYSEC-2026-1873)",
        "sphinx in the docs dependency group",
    ),
    "click": (
        Version("8.3.3"),
        "PYSEC-2026-2132",
        "litestar's CLI extras (runtime)",
    ),
    "idna": (
        Version("3.15"),
        "PYSEC-2026-215",
        "anyio/httpx via litestar (runtime)",
    ),
    "pygments": (
        Version("2.20.0"),
        "PYSEC-2026-2987",
        "rich via litestar (runtime)",
    ),
    "mako": (
        Version("1.3.12"),
        "PYSEC-2026-2617 (also PYSEC-2026-88)",
        "alembic via advanced-alchemy's `sqlalchemy` extra (runtime for that extra)",
    ),
}
"""Transitive dependencies with a known-vulnerable version below the given floor.

None of these are direct dependency-group entries, so each also carries a
``[tool.uv] constraint-dependencies`` pin (mirroring the ``multipart``
pattern above) to keep a relock in this repo's own lock/dev environment from
reintroducing the vulnerable version. Before this fix, uv.lock pinned
versions below every one of these floors and no constraint existed; these
assertions would have failed against that state.

``starlette`` and ``requests`` are transitive only through the docs
dependency group, so a ``[tool.uv]`` constraint is the only floor that makes
sense for them -- they never ship to a consumer installing this package.
``click``, ``idna``, ``pygments``, and ``mako`` (via the ``sqlalchemy``
extra), by contrast, are transitive *runtime* dependencies that reach every
consumer of the published package; for those,
``test_pyproject_dependencies_floor_excludes_vulnerable_transitive_version``
and ``test_pyproject_sqlalchemy_extra_floor_excludes_vulnerable_mako_version``
below additionally require a floor in published package metadata
(``[project.dependencies]`` or the relevant extra), since a
constraint-dependencies-only floor is invisible to a downstream resolver.
"""


@pytest.mark.parametrize(("package_name", "spec"), sorted(_TRANSITIVE_MIN_VERSIONS.items()))
def test_uv_lock_pins_transitive_dependency_above_vulnerable_version(
    package_name: str, spec: tuple[Version, str, str]
) -> None:
    """uv.lock must not pin a known-vulnerable version of a transitive dependency.

    Before this fix, uv.lock pinned starlette 0.50.0, requests 2.32.5,
    click 8.3.1, idna 3.11, pygments 2.19.2, and mako 1.3.10 -- all below
    their respective fixed versions -- so this assertion would have failed
    for each of them.
    """
    min_version, advisory, source = spec
    lock_data = tomllib.loads(_LOCK_FILE.read_text())
    entries = [pkg for pkg in lock_data["package"] if pkg["name"] == package_name]

    assert entries, f"{package_name} not found in uv.lock; expected it as a transitive dependency via {source}"

    for entry in entries:
        locked_version = Version(entry["version"])
        assert locked_version >= min_version, (
            f"uv.lock pins {package_name} {locked_version}, which is vulnerable to "
            f"{advisory}; run `uv lock --upgrade-package {package_name}` to update it."
        )


@pytest.mark.parametrize(("package_name", "spec"), sorted(_TRANSITIVE_MIN_VERSIONS.items()))
def test_installed_transitive_dependency_above_vulnerable_version(
    package_name: str, spec: tuple[Version, str, str]
) -> None:
    """The synced environment must match the lock file's fixed transitive dependency.

    Complements the uv.lock check above by catching an environment that
    drifted from the lock file (e.g. `.venv` synced before the lock was
    upgraded).
    """
    min_version, advisory, _source = spec
    try:
        installed_version = Version(importlib.metadata.version(package_name))
    except importlib.metadata.PackageNotFoundError:
        pytest.skip(f"{package_name} not installed")

    assert installed_version >= min_version, (
        f"{package_name} {installed_version} is vulnerable to {advisory}; run `uv sync` to match the updated lock file."
    )


@pytest.mark.parametrize(("package_name", "spec"), sorted(_TRANSITIVE_MIN_VERSIONS.items()))
def test_pyproject_constrains_transitive_dependency_above_vulnerable_version(
    package_name: str, spec: tuple[Version, str, str]
) -> None:
    """``pyproject.toml`` must pin a ``[tool.uv]`` constraint excluding each vulnerable range.

    Without an explicit ``[tool.uv] constraint-dependencies`` floor, a future
    relock could silently reintroduce the vulnerable release in this repo's
    own lock/dev environment. Before this fix, no such constraint existed for
    any of them and this assertion would have failed. Note that a
    constraint-dependencies entry alone does not protect a downstream
    consumer of the published package -- see
    ``test_pyproject_dependencies_floor_excludes_vulnerable_transitive_version``
    and ``test_pyproject_sqlalchemy_extra_floor_excludes_vulnerable_mako_version``
    for the floors that do.
    """
    min_version, advisory, _source = spec
    pyproject_data = tomllib.loads(_PYPROJECT_FILE.read_text())
    constraints = pyproject_data.get("tool", {}).get("uv", {}).get("constraint-dependencies", [])
    matching = [Requirement(dep) for dep in constraints if Requirement(dep).name == package_name]

    assert matching, (
        f"pyproject.toml has no [tool.uv] constraint-dependencies entry for {package_name}; "
        f"add one (e.g. '{package_name}>={min_version}') so a relock cannot reintroduce {advisory}"
    )

    for req in matching:
        assert req.marker is None, (
            f"{package_name} constraint {req!r} is gated by an environment marker; "
            f"a marked constraint leaves the unmatched environments unconstrained, which could "
            f"reintroduce {advisory} for them"
        )
        lower_bounds = [part.version for part in req.specifier if part.operator in (">=", ">", "==", "~=")]
        assert lower_bounds, f"{package_name} constraint {req!r} has no lower-bound specifier"
        assert all(Version(bound) >= min_version for bound in lower_bounds), (
            f"pyproject.toml's {package_name} constraint is {req!r}, which still permits versions "
            f"vulnerable to {advisory}"
        )


_PYTEST_MIN_VERSION = Version("9.0.3")
"""Versions below this are vulnerable to:

- PYSEC-2026-1845: vulnerable tmpdir handling, fixed in 9.0.3.

pytest is a direct dependency in the ``test`` dependency group, so its floor
in ``pyproject.toml`` is raised directly rather than via a ``[tool.uv]``
constraint.
"""


def test_uv_lock_pins_pytest_above_vulnerable_versions() -> None:
    """uv.lock must not pin a pytest affected by PYSEC-2026-1845.

    Before this fix, uv.lock pinned pytest 9.0.2, which is vulnerable; this
    assertion would have failed against that lock file.
    """
    lock_data = tomllib.loads(_LOCK_FILE.read_text())
    pytest_entries = [pkg for pkg in lock_data["package"] if pkg["name"] == "pytest"]

    assert pytest_entries, "pytest not found in uv.lock"

    for entry in pytest_entries:
        locked_version = Version(entry["version"])
        assert locked_version >= _PYTEST_MIN_VERSION, (
            f"uv.lock pins pytest {locked_version}, which is vulnerable to "
            "PYSEC-2026-1845; run `uv lock --upgrade-package pytest` to update it."
        )


def test_installed_pytest_above_vulnerable_versions() -> None:
    """The running pytest must match the lock file's fixed version.

    Complements the uv.lock check above by catching an environment that
    drifted from the lock file (e.g. `.venv` synced before the lock was
    upgraded).
    """
    installed_version = Version(importlib.metadata.version("pytest"))
    assert installed_version >= _PYTEST_MIN_VERSION, (
        f"pytest {installed_version} is vulnerable to PYSEC-2026-1845; run `uv sync` to match the updated lock file."
    )


def test_pyproject_pytest_floor_excludes_vulnerable_versions() -> None:
    """``pyproject.toml``'s ``pytest`` floor in the ``test`` group must exclude the vulnerable range.

    Before this fix, the floor was ``pytest>=8.0.0``, which lets a downstream
    resolver land on the vulnerable 9.0.2 release. This assertion would have
    failed against that floor.
    """
    pyproject_data = tomllib.loads(_PYPROJECT_FILE.read_text())
    test_group = pyproject_data["dependency-groups"]["test"]
    requirements = [Requirement(dep) for dep in test_group if isinstance(dep, str)]
    pytest_req = next((req for req in requirements if req.name == "pytest"), None)

    assert pytest_req is not None, "pytest not found in [dependency-groups.test]"

    lower_bounds = [spec.version for spec in pytest_req.specifier if spec.operator in (">=", ">", "==", "~=")]
    assert lower_bounds, f"pytest requirement {pytest_req!r} has no lower-bound specifier"
    assert all(Version(bound) >= _PYTEST_MIN_VERSION for bound in lower_bounds), (
        f"pyproject.toml's pytest requirement is {pytest_req!r}, which still permits versions "
        "vulnerable to PYSEC-2026-1845"
    )


def test_pyproject_constrains_multipart_above_vulnerable_version() -> None:
    """``pyproject.toml`` must pin a ``[tool.uv]`` constraint excluding the
    vulnerable multipart range.

    Since litestar's own dependency bound (``multipart>=1.2.0``) does not
    exclude the vulnerable 1.3.0 release, this project must also pin an
    explicit ``[tool.uv] constraint-dependencies`` floor, or a future relock
    could silently reintroduce PYSEC-2026-2670 in this repo's own lock/dev
    environment. Before this fix, no such constraint existed and this
    assertion would have failed. See
    ``test_pyproject_dependencies_floor_excludes_vulnerable_transitive_version``
    for the floor that also protects a downstream consumer of the published
    package.
    """
    pyproject_data = tomllib.loads(_PYPROJECT_FILE.read_text())
    constraints = pyproject_data.get("tool", {}).get("uv", {}).get("constraint-dependencies", [])
    multipart_constraints = [Requirement(dep) for dep in constraints if Requirement(dep).name == "multipart"]

    assert multipart_constraints, (
        "pyproject.toml has no [tool.uv] constraint-dependencies entry for multipart; "
        "add one (e.g. 'multipart>=1.3.1') so a relock cannot reintroduce PYSEC-2026-2670"
    )

    for multipart_req in multipart_constraints:
        assert multipart_req.marker is None, (
            f"multipart constraint {multipart_req!r} is gated by an environment marker; "
            "a marked constraint leaves the unmatched environments unconstrained, which could "
            "reintroduce PYSEC-2026-2670 for them"
        )
        lower_bounds = [spec.version for spec in multipart_req.specifier if spec.operator in (">=", ">", "==", "~=")]
        assert lower_bounds, f"multipart constraint {multipart_req!r} has no lower-bound specifier"
        assert all(Version(bound) >= _MULTIPART_MIN_VERSION for bound in lower_bounds), (
            f"pyproject.toml's multipart constraint is {multipart_req!r}, which still permits "
            "versions vulnerable to PYSEC-2026-2670"
        )


_PUBLISHED_RUNTIME_TRANSITIVE_MIN_VERSIONS = {
    "multipart": (_MULTIPART_MIN_VERSION, "PYSEC-2026-2670"),
    "click": (Version("8.3.3"), "PYSEC-2026-2132"),
    "idna": (Version("3.15"), "PYSEC-2026-215"),
    "pygments": (Version("2.20.0"), "PYSEC-2026-2987"),
}
"""Transitive runtime dependencies (via litestar) that must be floored in
``[project.dependencies]`` itself, not only in ``[tool.uv]
constraint-dependencies``.

``uv.lock``'s ``requires-dist`` for this package only ever reflects
``[project.dependencies]``/optional-dependencies entries (litestar, redis,
sqlalchemy, advanced-alchemy) -- a ``[tool.uv] constraint-dependencies``
pin only affects this repo's own lock/dev environment and is never
published. Without a matching ``[project.dependencies]`` floor, a
downstream consumer whose own resolver or constraints file pins e.g.
``click<8.3.3`` would still resolve a vulnerable click even with
litestar-api-auth installed, contrary to what the constraint-dependencies
comments claimed. Before this fix, none of these appeared in
``[project.dependencies]`` and this assertion would have failed for each.
"""


@pytest.mark.parametrize(("package_name", "spec"), sorted(_PUBLISHED_RUNTIME_TRANSITIVE_MIN_VERSIONS.items()))
def test_pyproject_dependencies_floor_excludes_vulnerable_transitive_version(
    package_name: str, spec: tuple[Version, str]
) -> None:
    """``[project.dependencies]`` must itself floor each transitive runtime dependency.

    This is the floor that reaches a downstream consumer's own dependency
    resolution (via ``requires-dist`` in the published package metadata),
    as opposed to the ``[tool.uv] constraint-dependencies`` entry, which
    only constrains this repo's own lock file. Before this fix,
    ``[project.dependencies]`` contained only ``litestar>=2.22.0`` and this
    assertion would have failed for every package below.
    """
    min_version, advisory = spec
    pyproject_data = tomllib.loads(_PYPROJECT_FILE.read_text())
    requirements = [Requirement(dep) for dep in pyproject_data["project"]["dependencies"]]
    req = next((r for r in requirements if r.name == package_name), None)

    assert req is not None, (
        f"{package_name} not found in [project.dependencies]; a [tool.uv] "
        f"constraint-dependencies floor alone does not protect a downstream "
        f"consumer from {advisory}, since it is never published in this "
        f"package's requires-dist metadata"
    )
    assert req.marker is None, (
        f"{package_name} requirement {req!r} is gated by an environment marker; a marked "
        f"requirement leaves the unmatched environments unfloored, which could reintroduce "
        f"{advisory} for them"
    )

    lower_bounds = [spec_item.version for spec_item in req.specifier if spec_item.operator in (">=", ">", "==", "~=")]
    assert lower_bounds, f"{package_name} requirement {req!r} has no lower-bound specifier"
    assert all(Version(bound) >= min_version for bound in lower_bounds), (
        f"pyproject.toml's {package_name} requirement is {req!r}, which still permits versions vulnerable to {advisory}"
    )


_MAKO_MIN_VERSION = Version("1.3.12")
"""Versions below this are vulnerable to PYSEC-2026-2617 (also PYSEC-2026-88), fixed in 1.3.12."""


def test_pyproject_sqlalchemy_extra_floor_excludes_vulnerable_mako_version() -> None:
    """The ``sqlalchemy`` optional-dependencies extra must itself floor mako.

    mako reaches a consumer only through ``litestar-api-auth[sqlalchemy]``
    (via advanced-alchemy's alembic dependency), so unlike the base runtime
    transitive dependencies above, its published floor belongs in the
    ``sqlalchemy`` extra rather than in ``[project.dependencies]``. A
    ``[tool.uv] constraint-dependencies`` entry alone is not published in
    this package's metadata and so does not protect a consumer installing
    that extra. Before this fix, the ``sqlalchemy`` extra contained only
    ``sqlalchemy>=2.0`` and ``advanced-alchemy>=0.20.0``, and this assertion
    would have failed.
    """
    pyproject_data = tomllib.loads(_PYPROJECT_FILE.read_text())
    sqlalchemy_extra = pyproject_data["project"]["optional-dependencies"]["sqlalchemy"]
    requirements = [Requirement(dep) for dep in sqlalchemy_extra]
    mako_req = next((r for r in requirements if r.name == "mako"), None)

    assert mako_req is not None, (
        "mako not found in the `sqlalchemy` optional-dependencies extra; a [tool.uv] "
        "constraint-dependencies floor alone does not protect a consumer installing "
        "litestar-api-auth[sqlalchemy] from PYSEC-2026-2617/PYSEC-2026-88, since it is "
        "never published in this package's requires-dist metadata"
    )
    assert mako_req.marker is None, (
        f"mako requirement {mako_req!r} in the sqlalchemy extra is gated by an environment "
        f"marker; a marked requirement leaves the unmatched environments unfloored even when "
        f"installing the extra, which could reintroduce PYSEC-2026-2617/PYSEC-2026-88 for them"
    )

    lower_bounds = [spec.version for spec in mako_req.specifier if spec.operator in (">=", ">", "==", "~=")]
    assert lower_bounds, f"mako requirement {mako_req!r} has no lower-bound specifier"
    assert all(Version(bound) >= _MAKO_MIN_VERSION for bound in lower_bounds), (
        f"pyproject.toml's mako requirement in the sqlalchemy extra is {mako_req!r}, which still "
        "permits versions vulnerable to PYSEC-2026-2617/PYSEC-2026-88"
    )
