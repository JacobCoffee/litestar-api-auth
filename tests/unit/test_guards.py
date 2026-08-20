"""Unit tests for guard type annotations.

These tests exercise the ``litestar_api_auth.guards`` module's type contract,
not just its runtime scope-checking behavior, since the bug they guard
against is invisible at runtime (both ``APIKeyInfo`` structs implement
``has_scope``/``has_scopes`` via duck typing) but visible to type checkers
and to anyone reading the annotation to decide what is safe to serialize.
"""

from __future__ import annotations

import typing
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from litestar.connection import ASGIConnection
from litestar.exceptions import NotAuthorizedException, PermissionDeniedException

from litestar_api_auth import guards
from litestar_api_auth.backends.base import APIKeyInfo as BackendAPIKeyInfo
from litestar_api_auth.guards import get_api_key_info, require_api_key, require_scope, require_scopes
from litestar_api_auth.types import APIKeyInfo as PublicAPIKeyInfo


def _connection_with_state_api_key(value: object) -> ASGIConnection:
    """Build an ASGIConnection whose ``state["api_key"]`` is exactly `value`.

    Mirrors ``_make_scope`` in ``test_middleware.py``: this simulates a value
    landing in the generic, unnamespaced "api_key" state key from *some*
    source other than ``APIKeyMiddleware`` validating a key on this request
    (another middleware/dependency/handler, or a route excluded from
    ``APIKeyMiddleware`` entirely), which is exactly what
    ``get_api_key_info`` must not blindly trust.
    """
    scope: dict[str, Any] = {"type": "http", "headers": [], "state": {"api_key": value}}
    return ASGIConnection(scope)  # type: ignore[arg-type]


class TestGetApiKeyInfoAnnotation:
    """Regression tests: guards must annotate the type the middleware
    actually stores in ``request.state.api_key``.

    ``APIKeyMiddleware`` (middleware.py) only ever stores the canonical
    ``APIKeyInfo`` -- the mutable struct that carries ``key_hash`` -- in
    ``scope["state"]["api_key"]``. Before this fix, ``guards.py`` imported
    and annotated the unrelated, frozen ``types.APIKeyInfo`` (which had no
    ``key_hash`` field) instead. Code written against that annotation would
    have no static indication that the real object carries a secret hash,
    risking accidental disclosure if such an object were ever serialized,
    and would also be checking the wrong struct's shape for
    ``is_active``/``is_expired``.

    The two structs have since been consolidated into one class, so this now
    also pins that consolidation: ``backends.base.APIKeyInfo`` and
    ``types.APIKeyInfo`` must remain the *same* object, or the annotation
    could silently drift apart from the runtime type again.
    """

    def test_public_and_backend_api_key_info_are_the_same_class(self) -> None:
        """The two historical import paths must resolve to one canonical class."""
        assert BackendAPIKeyInfo is PublicAPIKeyInfo

    def test_guards_module_imports_canonical_api_key_info(self) -> None:
        """``guards.APIKeyInfo`` must be the canonical struct."""
        assert guards.APIKeyInfo is BackendAPIKeyInfo
        assert guards.APIKeyInfo is PublicAPIKeyInfo

    def test_get_api_key_info_return_annotation_matches_runtime_type(self) -> None:
        """The declared return type of ``get_api_key_info`` must match what
        ``APIKeyMiddleware`` actually places in request state.
        """
        hints = typing.get_type_hints(guards.get_api_key_info)
        assert hints["return"] is BackendAPIKeyInfo


class TestStateTrustBoundary:
    """Regression tests: guards must not trust a merely non-``None``
    ``state["api_key"]`` as proof of authentication.

    ``state["api_key"]`` is a generic, unnamespaced key. Before this fix,
    ``get_api_key_info`` only checked ``is None``, so any other in-process
    code that wrote a non-``None`` value there -- a forged/stale/wrong-type
    object, including one planted on a route matched by
    ``APIKeyMiddleware``'s ``exclude_paths`` where the middleware's own
    clear-on-entry never runs -- would satisfy ``require_api_key``, and
    ``require_scope``/``require_scopes`` would trust whatever ``scopes`` it
    claimed to have, even if the forged object were inactive and expired.

    These tests cover the fix's stated threat model: an accidental/buggy
    state-key collision from other server-side code, which is what the
    isinstance + is_active + is_expired check defends against. A fully
    malicious actor with arbitrary in-process code execution could still
    construct a well-formed, active, non-expired ``APIKeyInfo`` -- but at
    that point they could equally patch the guard itself, which is outside
    what any in-process object check can defend against.
    """

    def test_non_apikeyinfo_non_none_value_fails_require_api_key(self) -> None:
        """A non-``APIKeyInfo`` value that merely isn't ``None`` must not pass.

        Before the fix, ``get_api_key_info`` only checked ``is None``, so
        ``state["api_key"] = 0`` -- not None, even though ``0`` itself is
        falsy -- was returned as-is and ``require_api_key`` passed.
        """
        connection = _connection_with_state_api_key(0)

        with pytest.raises(NotAuthorizedException):
            get_api_key_info(connection)

        with pytest.raises(NotAuthorizedException):
            require_api_key(connection, None)  # type: ignore[arg-type]

    def test_forged_inactive_expired_key_fails_require_scope(self) -> None:
        """A forged ``APIKeyInfo`` that is revoked *and* expired must not
        satisfy ``require_scope``, even though it claims the right scope.

        Before the fix, ``get_api_key_info`` returned any non-None value
        unconditionally, so ``require_scope`` only checked
        ``key_info.has_scope(...)`` against attacker-controlled data and
        never re-validated ``is_active``/``is_expired``.
        """
        forged = BackendAPIKeyInfo(
            key_id="forged",
            key_hash="",
            name="Forged Admin Key",
            scopes=["admin"],
            is_active=False,
            expires_at=datetime.now(timezone.utc) - timedelta(days=1),
        )
        connection = _connection_with_state_api_key(forged)

        with pytest.raises(NotAuthorizedException):
            require_scope("admin")(connection, None)  # type: ignore[arg-type]

    def test_malformed_record_fails_require_scope_despite_substring_match(self) -> None:
        """A record with non-conforming field types must not satisfy ``require_scope``.

        ``msgspec.Struct`` does not type-check on direct construction, so a
        custom/legacy backend, migrated or corrupted data, or direct
        programmatic seeding could land exactly this in state: ``is_active``
        as the truthy string ``"false"`` and ``scopes`` as a plain ``str``.
        Before the fix, ``not "false"`` is ``False`` (so the active check
        passed) and ``"admin" in "api_keys:admin"`` is a substring match
        (so ``has_scope("admin")`` incorrectly returned True) -- reachable
        end-to-end through the real middleware+guard.
        """
        malformed = BackendAPIKeyInfo(
            key_id="malformed",
            key_hash="",
            name="Malformed",
            scopes="api_keys:admin",  # type: ignore[arg-type]
            is_active="false",  # type: ignore[arg-type]
        )
        connection = _connection_with_state_api_key(malformed)

        with pytest.raises(NotAuthorizedException):
            require_api_key(connection, None)  # type: ignore[arg-type]

        with pytest.raises(NotAuthorizedException):
            require_scope("admin")(connection, None)  # type: ignore[arg-type]

    def test_forged_active_but_expired_key_fails(self) -> None:
        """An expired key that is still marked active must still be rejected."""
        forged = BackendAPIKeyInfo(
            key_id="forged-expired",
            key_hash="",
            name="Forged Expired Key",
            scopes=["admin"],
            is_active=True,
            expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
        )
        connection = _connection_with_state_api_key(forged)

        with pytest.raises(NotAuthorizedException):
            require_api_key(connection, None)  # type: ignore[arg-type]

    def test_valid_key_still_passes(self) -> None:
        """Sanity check: a genuine, active, non-expired key is unaffected."""
        valid = BackendAPIKeyInfo(
            key_id="real",
            key_hash="",
            name="Real Key",
            scopes=["admin"],
            is_active=True,
            expires_at=datetime.now(timezone.utc) + timedelta(days=1),
        )
        connection = _connection_with_state_api_key(valid)

        require_api_key(connection, None)  # type: ignore[arg-type]  # must not raise
        require_scope("admin")(connection, None)  # type: ignore[arg-type]  # must not raise

        with pytest.raises(PermissionDeniedException):
            require_scope("billing")(connection, None)  # type: ignore[arg-type]


class TestScopeDisclosure:
    """Regression tests: 403 responses must not echo the key's granted
    scopes back to the caller.

    Before this fix, ``require_scope``/``require_scopes`` included
    ``key_info.scopes`` -- the full list of scopes actually granted to the
    presented key -- in the ``PermissionDeniedException`` detail. A caller
    holding a stolen or shared low-privilege key could probe a guarded route
    and have the 403 body enumerate exactly what that key is allowed to do,
    with no management-scope access required. The *required* scopes (which
    are baked into the route's guard configuration and are not secret) may
    still be reported.
    """

    def _key_with_scopes(self, *scopes: str) -> BackendAPIKeyInfo:
        return BackendAPIKeyInfo(
            key_id="low-priv",
            key_hash="",
            name="Low Privilege Key",
            scopes=list(scopes),
            is_active=True,
            expires_at=datetime.now(timezone.utc) + timedelta(days=1),
        )

    def test_require_scope_403_does_not_echo_available_scopes(self) -> None:
        key_info = self._key_with_scopes("read:public", "billing:secret-project")
        connection = _connection_with_state_api_key(key_info)

        with pytest.raises(PermissionDeniedException) as exc_info:
            require_scope("admin:write")(connection, None)  # type: ignore[arg-type]

        detail = str(exc_info.value.detail)
        assert "read:public" not in detail
        assert "billing:secret-project" not in detail

    def test_require_scopes_all_403_does_not_echo_available_scopes(self) -> None:
        key_info = self._key_with_scopes("read:public", "billing:secret-project")
        connection = _connection_with_state_api_key(key_info)

        with pytest.raises(PermissionDeniedException) as exc_info:
            require_scopes("admin:read", "users:write")(connection, None)  # type: ignore[arg-type]

        detail = str(exc_info.value.detail)
        assert "read:public" not in detail
        assert "billing:secret-project" not in detail

    def test_require_scopes_any_403_does_not_echo_available_scopes(self) -> None:
        key_info = self._key_with_scopes("read:public", "billing:secret-project")
        connection = _connection_with_state_api_key(key_info)

        with pytest.raises(PermissionDeniedException) as exc_info:
            require_scopes("admin:read", "admin:write", match="any")(connection, None)  # type: ignore[arg-type]

        detail = str(exc_info.value.detail)
        assert "read:public" not in detail
        assert "billing:secret-project" not in detail
