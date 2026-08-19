"""Unit tests for guard type annotations.

These tests exercise the ``litestar_api_auth.guards`` module's type contract,
not just its runtime scope-checking behavior, since the bug they guard
against is invisible at runtime (both ``APIKeyInfo`` structs implement
``has_scope``/``has_scopes`` via duck typing) but visible to type checkers
and to anyone reading the annotation to decide what is safe to serialize.
"""

from __future__ import annotations

import typing

from litestar_api_auth import guards
from litestar_api_auth.backends.base import APIKeyInfo as BackendAPIKeyInfo
from litestar_api_auth.types import APIKeyInfo as PublicAPIKeyInfo


class TestGetApiKeyInfoAnnotation:
    """Regression tests: guards must annotate the type the middleware
    actually stores in ``request.state.api_key``.

    ``APIKeyMiddleware`` (middleware.py) only ever stores
    ``backends.base.APIKeyInfo`` -- the mutable struct that carries
    ``key_hash`` -- in ``scope["state"]["api_key"]``. Before this fix,
    ``guards.py`` imported and annotated the unrelated, frozen
    ``types.APIKeyInfo`` (which has no ``key_hash`` field) instead. Code
    written against that annotation would have no static indication that
    the real object carries a secret hash, risking accidental disclosure
    if such an object were ever serialized, and would also be checking
    the wrong struct's shape for `is_active`/`is_expired`.
    """

    def test_guards_module_imports_backend_api_key_info(self) -> None:
        """``guards.APIKeyInfo`` must be the backend struct, not the public one."""
        assert guards.APIKeyInfo is BackendAPIKeyInfo
        assert guards.APIKeyInfo is not PublicAPIKeyInfo

    def test_get_api_key_info_return_annotation_matches_runtime_type(self) -> None:
        """The declared return type of ``get_api_key_info`` must match what
        ``APIKeyMiddleware`` actually places in request state.
        """
        hints = typing.get_type_hints(guards.get_api_key_info)
        assert hints["return"] is BackendAPIKeyInfo
