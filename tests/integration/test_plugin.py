"""Integration tests for the APIAuthPlugin with Litestar TestClient.

These tests verify that the plugin correctly integrates with Litestar
applications, including middleware, guards, and dependency injection.
"""

from __future__ import annotations

import hashlib

import pytest
from litestar import Litestar, get
from litestar.config.app import AppConfig
from litestar.testing import TestClient

from litestar_api_auth import APIAuthConfig, APIAuthPlugin, ConfigurationError, require_api_key
from litestar_api_auth.backends.base import APIKeyInfo
from litestar_api_auth.backends.memory import MemoryBackend
from litestar_api_auth.guards import require_scope, require_scopes
from litestar_api_auth.service import generate_api_key


@pytest.fixture
def backend() -> MemoryBackend:
    """Create a fresh memory backend for each test."""
    return MemoryBackend()


@pytest.fixture
def test_api_key(backend: MemoryBackend) -> tuple[str, str, APIKeyInfo]:
    """Create a test API key in the backend.

    Returns:
        Tuple of (raw_key, hashed_key, key_info)
    """
    raw_key, hashed_key = generate_api_key(prefix="test_")
    key_info = APIKeyInfo(
        key_id="test-key-123",
        key_hash=hashed_key,
        name="Test Key",
        scopes=["read:users", "write:posts"],
        is_active=True,
    )
    return raw_key, hashed_key, key_info


@pytest.fixture
async def seeded_backend(backend: MemoryBackend, test_api_key: tuple[str, str, APIKeyInfo]) -> MemoryBackend:
    """Create a backend with a pre-seeded API key."""
    _raw_key, hashed_key, key_info = test_api_key
    await backend.create(hashed_key, key_info)
    return backend


class TestPluginIntegration:
    """Test APIAuthPlugin integration with Litestar."""

    def test_plugin_initializes_without_error(self, backend: MemoryBackend) -> None:
        """Test that the plugin can be initialized and added to an app."""
        app = Litestar(
            route_handlers=[],
            plugins=[
                APIAuthPlugin(
                    config=APIAuthConfig(
                        backend=backend,
                        key_prefix="test_",
                        auto_routes=False,
                    )
                )
            ],
        )
        assert app is not None

    def test_plugin_with_auto_routes(self, backend: MemoryBackend) -> None:
        """Test that auto routes are registered when enabled."""
        app = Litestar(
            route_handlers=[],
            plugins=[
                APIAuthPlugin(
                    config=APIAuthConfig(
                        backend=backend,
                        auto_routes=True,
                        route_prefix="/api-keys",
                    )
                )
            ],
        )
        # Check that routes were registered
        route_paths = [route.path for route in app.routes]
        assert any("/api-keys" in path for path in route_paths)


class TestManagementRouteAuthorization:
    """Regression tests: auto-registered key-management routes must be guarded.

    Before the fix, ``auto_routes=True`` (the default) registered
    ``APIKeyController`` with no guards at all, so anyone -- authenticated or
    not -- could create, list, revoke, or delete API keys, including minting
    a brand new key with arbitrary (e.g. admin) scopes.
    """

    @pytest.mark.integration
    async def test_create_key_route_rejects_anonymous_caller(self, backend: MemoryBackend) -> None:
        """POST /api-keys must reject a request with no API key at all."""
        app = Litestar(
            route_handlers=[],
            plugins=[
                APIAuthPlugin(
                    config=APIAuthConfig(
                        backend=backend,
                        auto_routes=True,
                    )
                )
            ],
        )

        with TestClient(app) as client:
            response = client.post("/api-keys/", json={"name": "attacker-key", "scopes": ["admin:all"]})

        assert response.status_code == 401

    @pytest.mark.integration
    async def test_list_keys_route_rejects_anonymous_caller(self, backend: MemoryBackend) -> None:
        """GET /api-keys must reject a request with no API key, preventing enumeration."""
        app = Litestar(
            route_handlers=[],
            plugins=[
                APIAuthPlugin(
                    config=APIAuthConfig(
                        backend=backend,
                        auto_routes=True,
                    )
                )
            ],
        )

        with TestClient(app) as client:
            response = client.get("/api-keys/")

        assert response.status_code == 401

    @pytest.mark.integration
    async def test_create_key_route_rejects_low_privilege_key(
        self, seeded_backend: MemoryBackend, test_api_key: tuple[str, str, APIKeyInfo]
    ) -> None:
        """A valid key lacking the admin scope must not be able to mint new keys.

        This is the scope-escalation half of the finding: requiring merely
        *any* valid API key would still let a low-privilege key create a new
        key carrying higher-privilege scopes.
        """
        raw_key, _, _ = test_api_key

        app = Litestar(
            route_handlers=[],
            plugins=[
                APIAuthPlugin(
                    config=APIAuthConfig(
                        backend=seeded_backend,
                        auto_routes=True,
                    )
                )
            ],
        )

        with TestClient(app) as client:
            response = client.post(
                "/api-keys/",
                headers={"X-API-Key": raw_key},
                json={"name": "escalated-key", "scopes": ["admin:all"]},
            )

        assert response.status_code == 403

    @pytest.mark.integration
    async def test_create_key_route_allows_admin_scoped_key(self, backend: MemoryBackend) -> None:
        """A key holding the default ``api_keys:admin`` scope can manage keys."""
        raw_admin_key, hashed_admin_key = generate_api_key(prefix="test_")
        await backend.create(
            hashed_admin_key,
            APIKeyInfo(
                key_id="admin-key-123",
                key_hash=hashed_admin_key,
                name="Admin Key",
                scopes=["api_keys:admin"],
                is_active=True,
            ),
        )

        app = Litestar(
            route_handlers=[],
            plugins=[
                APIAuthPlugin(
                    config=APIAuthConfig(
                        backend=backend,
                        auto_routes=True,
                    )
                )
            ],
        )

        with TestClient(app) as client:
            response = client.post(
                "/api-keys/",
                headers={"X-API-Key": raw_admin_key},
                json={"name": "new-key", "scopes": ["read:users"]},
            )

        assert response.status_code == 201

    @pytest.mark.integration
    @pytest.mark.parametrize(
        ("method", "path_suffix"),
        [
            ("get", "some-key-id"),
            ("post", "some-key-id/revoke"),
            ("delete", "some-key-id"),
        ],
    )
    async def test_remaining_management_routes_reject_anonymous_caller(
        self, backend: MemoryBackend, method: str, path_suffix: str
    ) -> None:
        """GET/revoke/DELETE by key_id must also reject requests with no API key."""
        app = Litestar(
            route_handlers=[],
            plugins=[
                APIAuthPlugin(
                    config=APIAuthConfig(
                        backend=backend,
                        auto_routes=True,
                    )
                )
            ],
        )

        with TestClient(app) as client:
            response = getattr(client, method)(f"/api-keys/{path_suffix}")

        assert response.status_code == 401

    @pytest.mark.integration
    async def test_manually_registered_controller_rejects_anonymous_caller(self, backend: MemoryBackend) -> None:
        """APIKeyController must be guarded even when registered manually (auto_routes=False).

        The controller's own default guard (not just the plugin's auto-route
        wiring) must reject unauthenticated callers, since the docs show it
        being registered directly as a route handler.
        """
        from litestar.di import Provide

        from litestar_api_auth.controllers import APIKeyController

        app = Litestar(
            route_handlers=[APIKeyController],
            dependencies={"backend": Provide(lambda: backend, sync_to_thread=False)},
            plugins=[
                APIAuthPlugin(
                    config=APIAuthConfig(
                        backend=backend,
                        auto_routes=False,
                    )
                )
            ],
        )

        with TestClient(app) as client:
            response = client.get("/api-keys/")

        assert response.status_code == 401

    @pytest.mark.integration
    async def test_manually_registered_controller_allows_admin_scoped_key(self, backend: MemoryBackend) -> None:
        """The manually-registered controller must also *authorize* an admin-scoped
        key, not just reject anonymous callers -- confirming the class docstring's
        example (plugin installed with ``auto_routes=False`` alongside an explicit
        ``backend`` dependency) actually results in a working, guarded route.
        """
        from litestar.di import Provide

        from litestar_api_auth.controllers import APIKeyController

        raw_admin_key, hashed_admin_key = generate_api_key(prefix="test_")
        await backend.create(
            hashed_admin_key,
            APIKeyInfo(
                key_id="admin-key-manual",
                key_hash=hashed_admin_key,
                name="Admin Key",
                scopes=["api_keys:admin"],
                is_active=True,
            ),
        )

        app = Litestar(
            route_handlers=[APIKeyController],
            dependencies={"backend": Provide(lambda: backend, sync_to_thread=False)},
            plugins=[
                APIAuthPlugin(
                    config=APIAuthConfig(
                        backend=backend,
                        auto_routes=False,
                    )
                )
            ],
        )

        with TestClient(app) as client:
            response = client.get("/api-keys/", headers={"X-API-Key": raw_admin_key})

        assert response.status_code == 200

    @pytest.mark.integration
    async def test_list_keys_route_rejects_low_privilege_key(
        self, seeded_backend: MemoryBackend, test_api_key: tuple[str, str, APIKeyInfo]
    ) -> None:
        """A valid key lacking the admin scope must not be able to enumerate keys."""
        raw_key, _, _ = test_api_key

        app = Litestar(
            route_handlers=[],
            plugins=[
                APIAuthPlugin(
                    config=APIAuthConfig(
                        backend=seeded_backend,
                        auto_routes=True,
                    )
                )
            ],
        )

        with TestClient(app) as client:
            response = client.get("/api-keys/", headers={"X-API-Key": raw_key})

        assert response.status_code == 403

    @pytest.mark.integration
    async def test_list_keys_route_allows_admin_scoped_key(self, seeded_backend: MemoryBackend) -> None:
        """A key holding the default ``api_keys:admin`` scope can enumerate keys."""
        raw_admin_key, hashed_admin_key = generate_api_key(prefix="test_")
        await seeded_backend.create(
            hashed_admin_key,
            APIKeyInfo(
                key_id="admin-key-list",
                key_hash=hashed_admin_key,
                name="Admin Key",
                scopes=["api_keys:admin"],
                is_active=True,
            ),
        )

        app = Litestar(
            route_handlers=[],
            plugins=[
                APIAuthPlugin(
                    config=APIAuthConfig(
                        backend=seeded_backend,
                        auto_routes=True,
                    )
                )
            ],
        )

        with TestClient(app) as client:
            response = client.get("/api-keys/", headers={"X-API-Key": raw_admin_key})

        assert response.status_code == 200

    @pytest.mark.integration
    @pytest.mark.parametrize(
        ("method", "path_suffix"),
        [
            ("get", "test-key-123"),
            ("post", "test-key-123/revoke"),
            ("delete", "test-key-123"),
        ],
    )
    async def test_remaining_management_routes_reject_low_privilege_key(
        self,
        seeded_backend: MemoryBackend,
        test_api_key: tuple[str, str, APIKeyInfo],
        method: str,
        path_suffix: str,
    ) -> None:
        """A valid key lacking the admin scope must not reach GET/revoke/DELETE either.

        This closes the same gap ``test_create_key_route_rejects_low_privilege_key``
        closes for creation, but for the remaining four routes: requiring merely
        *any* valid API key (rather than the ``api_keys:admin`` scope specifically)
        would still let a low-privilege key read, revoke, or delete *any* key,
        including ones it didn't create.
        """
        raw_key, _, _ = test_api_key

        app = Litestar(
            route_handlers=[],
            plugins=[
                APIAuthPlugin(
                    config=APIAuthConfig(
                        backend=seeded_backend,
                        auto_routes=True,
                    )
                )
            ],
        )

        with TestClient(app) as client:
            response = getattr(client, method)(f"/api-keys/{path_suffix}", headers={"X-API-Key": raw_key})

        assert response.status_code == 403

    @pytest.mark.integration
    @pytest.mark.parametrize(
        ("method", "path_suffix", "expected_status"),
        [
            ("get", "test-key-123", 200),
            ("post", "test-key-123/revoke", 204),
            ("delete", "test-key-123", 204),
        ],
    )
    async def test_remaining_management_routes_allow_admin_scoped_key(
        self,
        seeded_backend: MemoryBackend,
        method: str,
        path_suffix: str,
        expected_status: int,
    ) -> None:
        """A key holding the default ``api_keys:admin`` scope can reach GET/revoke/DELETE too.

        Guards against over-restricting the fix: the ``api_keys:admin`` scope
        requirement must still let a properly-privileged caller manage keys,
        not merely reject everyone else.
        """
        raw_admin_key, hashed_admin_key = generate_api_key(prefix="test_")
        await seeded_backend.create(
            hashed_admin_key,
            APIKeyInfo(
                key_id="admin-key-remaining",
                key_hash=hashed_admin_key,
                name="Admin Key",
                scopes=["api_keys:admin"],
                is_active=True,
            ),
        )

        app = Litestar(
            route_handlers=[],
            plugins=[
                APIAuthPlugin(
                    config=APIAuthConfig(
                        backend=seeded_backend,
                        auto_routes=True,
                    )
                )
            ],
        )

        with TestClient(app) as client:
            response = getattr(client, method)(f"/api-keys/{path_suffix}", headers={"X-API-Key": raw_admin_key})

        assert response.status_code == expected_status


class TestRevokeReturnValueIsRespected:
    """Regression test: the revoke endpoint must not ignore a failed revoke().

    ``backend.create()`` now refuses to store a record whose ``info.key_hash``
    disagrees with the ``key_hash`` argument (see ``TestMemoryBackendCreate``
    in ``tests/test_backends.py``), which is what used to let such a record
    into storage in the first place. But a record can still end up with a
    ``key_hash`` that doesn't resolve to anything in the primary store --
    e.g. data restored from an older version of this library, or a store
    edited directly outside the API -- and previously
    ``APIKeyController.revoke_api_key`` ignored ``backend.revoke()``'s
    ``False`` return in that case, responding 204 as if the key had been
    revoked when it hadn't been touched at all.
    """

    @pytest.mark.integration
    async def test_revoke_route_returns_404_when_backend_cannot_revoke(
        self,
        seeded_backend: MemoryBackend,
        test_api_key: tuple[str, str, APIKeyInfo],
    ) -> None:
        """Revoking a key whose key_hash doesn't resolve must 404, not 204."""
        _raw_key, hashed_key, _key_info = test_api_key

        # Simulate a record that has drifted out of sync with the primary
        # store -- the state create()'s new validation now prevents, but
        # which can still arise from data restored from an older version of
        # this library or a store edited outside the API. get_by_id() must
        # keep returning it (it's still "the record for this key_id"), but
        # its key_hash no longer resolves to anything revoke()/delete() can find.
        seeded_backend._store[hashed_key] = APIKeyInfo(
            key_id="test-key-123",
            key_hash="stale-hash-that-does-not-exist-in-store",
            name="Test Key",
            scopes=["read:users", "write:posts"],
            is_active=True,
        )

        raw_admin_key, hashed_admin_key = generate_api_key(prefix="test_")
        await seeded_backend.create(
            hashed_admin_key,
            APIKeyInfo(
                key_id="admin-key-revoke-integrity",
                key_hash=hashed_admin_key,
                name="Admin Key",
                scopes=["api_keys:admin"],
                is_active=True,
            ),
        )

        app = Litestar(
            route_handlers=[],
            plugins=[
                APIAuthPlugin(
                    config=APIAuthConfig(
                        backend=seeded_backend,
                        auto_routes=True,
                    )
                )
            ],
        )

        with TestClient(app) as client:
            response = client.post(
                "/api-keys/test-key-123/revoke",
                headers={"X-API-Key": raw_admin_key},
            )

            assert response.status_code == 404

            # The record itself must be untouched -- still active, i.e.
            # genuinely not revoked, rather than silently reported as
            # revoked. Checked inside the `with` block: TestClient's
            # __exit__ fires the plugin's on_shutdown hook, which calls
            # backend.close() and clears the in-memory store.
            untouched = await seeded_backend.get(hashed_key)
            assert untouched is not None
            assert untouched.is_active is True


class TestMiddlewareIntegration:
    """Test middleware integration with protected routes."""

    @pytest.mark.integration
    async def test_unprotected_route_works_without_key(self, backend: MemoryBackend) -> None:
        """Test that unprotected routes work without an API key."""

        @get("/public")
        async def public_route() -> dict:
            return {"message": "public"}

        app = Litestar(
            route_handlers=[public_route],
            plugins=[
                APIAuthPlugin(
                    config=APIAuthConfig(
                        backend=backend,
                        auto_routes=False,
                    )
                )
            ],
        )

        with TestClient(app) as client:
            response = client.get("/public")
            assert response.status_code == 200
            assert response.json() == {"message": "public"}

    @pytest.mark.integration
    async def test_protected_route_requires_api_key(self, backend: MemoryBackend) -> None:
        """Test that protected routes require a valid API key."""

        @get("/protected", guards=[require_api_key])
        async def protected_route() -> dict:
            return {"message": "protected"}

        app = Litestar(
            route_handlers=[protected_route],
            plugins=[
                APIAuthPlugin(
                    config=APIAuthConfig(
                        backend=backend,
                        auto_routes=False,
                    )
                )
            ],
        )

        with TestClient(app) as client:
            # Without API key should fail
            response = client.get("/protected")
            assert response.status_code == 401

    @pytest.mark.integration
    async def test_protected_route_with_valid_key(
        self, seeded_backend: MemoryBackend, test_api_key: tuple[str, str, APIKeyInfo]
    ) -> None:
        """Test that protected routes work with a valid API key."""
        raw_key, _, _ = test_api_key

        @get("/protected", guards=[require_api_key])
        async def protected_route() -> dict:
            return {"message": "protected"}

        app = Litestar(
            route_handlers=[protected_route],
            plugins=[
                APIAuthPlugin(
                    config=APIAuthConfig(
                        backend=seeded_backend,
                        auto_routes=False,
                    )
                )
            ],
        )

        with TestClient(app) as client:
            response = client.get("/protected", headers={"X-API-Key": raw_key})
            assert response.status_code == 200
            assert response.json() == {"message": "protected"}

    @pytest.mark.integration
    async def test_protected_route_with_invalid_key(self, seeded_backend: MemoryBackend) -> None:
        """Test that protected routes reject invalid API keys."""

        @get("/protected", guards=[require_api_key])
        async def protected_route() -> dict:
            return {"message": "protected"}

        app = Litestar(
            route_handlers=[protected_route],
            plugins=[
                APIAuthPlugin(
                    config=APIAuthConfig(
                        backend=seeded_backend,
                        auto_routes=False,
                    )
                )
            ],
        )

        with TestClient(app) as client:
            response = client.get("/protected", headers={"X-API-Key": "invalid_key_12345"})
            assert response.status_code == 401


class TestExcludePaths:
    """Regression tests: ``APIAuthConfig.exclude_paths`` must actually be honored.

    Before the fix, ``exclude_paths`` was documented as excluding paths from
    authentication but was never passed to the middleware, so the middleware
    hashed and looked up the key (and bumped ``last_used_at``) for every
    request regardless of ``exclude_paths``.
    """

    @pytest.mark.integration
    async def test_excluded_path_skips_backend_lookup(
        self, seeded_backend: MemoryBackend, test_api_key: tuple[str, str, APIKeyInfo]
    ) -> None:
        """A request to an excluded path must bypass the middleware entirely.

        Even when a valid ``X-API-Key`` header is present, the backend must
        not be consulted (no ``get`` lookup, no ``update_last_used`` call)
        for a path listed in ``exclude_paths``.
        """
        raw_key, _, _ = test_api_key

        get_calls = 0
        update_calls = 0
        original_get = seeded_backend.get
        original_update_last_used = seeded_backend.update_last_used

        async def counting_get(key_hash: str) -> APIKeyInfo | None:
            nonlocal get_calls
            get_calls += 1
            return await original_get(key_hash)

        async def counting_update_last_used(key_hash: str) -> None:
            nonlocal update_calls
            update_calls += 1
            await original_update_last_used(key_hash)

        seeded_backend.get = counting_get  # type: ignore[method-assign]
        seeded_backend.update_last_used = counting_update_last_used  # type: ignore[method-assign]

        @get("/health")
        async def health_route() -> dict:
            return {"status": "ok"}

        app = Litestar(
            route_handlers=[health_route],
            plugins=[
                APIAuthPlugin(
                    config=APIAuthConfig(
                        backend=seeded_backend,
                        auto_routes=False,
                        exclude_paths=["/health"],
                    )
                )
            ],
        )

        with TestClient(app) as client:
            response = client.get("/health", headers={"X-API-Key": raw_key})

        assert response.status_code == 200
        assert get_calls == 0
        assert update_calls == 0

    @pytest.mark.integration
    async def test_non_excluded_path_still_enforces_auth(
        self, seeded_backend: MemoryBackend, test_api_key: tuple[str, str, APIKeyInfo]
    ) -> None:
        """Sanity check: paths not in ``exclude_paths`` still go through the middleware.

        Uses a *valid* key and asserts success, rather than asserting a 401 for
        an anonymous request -- a 401 would happen whether or not the middleware
        ran at all, so it wouldn't actually prove the middleware still processes
        non-excluded paths after wiring up ``exclude_paths``.
        """
        raw_key, _, _ = test_api_key

        @get("/protected", guards=[require_api_key])
        async def protected_route() -> dict:
            return {"message": "protected"}

        app = Litestar(
            route_handlers=[protected_route],
            plugins=[
                APIAuthPlugin(
                    config=APIAuthConfig(
                        backend=seeded_backend,
                        auto_routes=False,
                        exclude_paths=["/health"],
                    )
                )
            ],
        )

        with TestClient(app) as client:
            response = client.get("/protected", headers={"X-API-Key": raw_key})

        assert response.status_code == 200
        assert response.json() == {"message": "protected"}


class TestScopeGuardsIntegration:
    """Test scope-based authorization guards."""

    @pytest.mark.integration
    async def test_require_scope_grants_access(
        self, seeded_backend: MemoryBackend, test_api_key: tuple[str, str, APIKeyInfo]
    ) -> None:
        """Test that require_scope grants access when scope is present."""
        raw_key, _, _ = test_api_key

        @get("/users", guards=[require_scope("read:users")])
        async def read_users() -> dict:
            return {"users": []}

        app = Litestar(
            route_handlers=[read_users],
            plugins=[
                APIAuthPlugin(
                    config=APIAuthConfig(
                        backend=seeded_backend,
                        auto_routes=False,
                    )
                )
            ],
        )

        with TestClient(app) as client:
            response = client.get("/users", headers={"X-API-Key": raw_key})
            assert response.status_code == 200

    @pytest.mark.integration
    async def test_require_scope_denies_access(
        self, seeded_backend: MemoryBackend, test_api_key: tuple[str, str, APIKeyInfo]
    ) -> None:
        """Test that require_scope denies access when scope is missing."""
        raw_key, _, _ = test_api_key

        @get("/admin", guards=[require_scope("admin:all")])
        async def admin_route() -> dict:
            return {"admin": True}

        app = Litestar(
            route_handlers=[admin_route],
            plugins=[
                APIAuthPlugin(
                    config=APIAuthConfig(
                        backend=seeded_backend,
                        auto_routes=False,
                    )
                )
            ],
        )

        with TestClient(app) as client:
            response = client.get("/admin", headers={"X-API-Key": raw_key})
            assert response.status_code == 403

    @pytest.mark.integration
    async def test_require_scopes_all(
        self, seeded_backend: MemoryBackend, test_api_key: tuple[str, str, APIKeyInfo]
    ) -> None:
        """Test require_scopes with 'all' requirement."""
        raw_key, _, _ = test_api_key

        @get("/multi", guards=[require_scopes("read:users", "write:posts", match="all")])
        async def multi_scope_route() -> dict:
            return {"access": "granted"}

        app = Litestar(
            route_handlers=[multi_scope_route],
            plugins=[
                APIAuthPlugin(
                    config=APIAuthConfig(
                        backend=seeded_backend,
                        auto_routes=False,
                    )
                )
            ],
        )

        with TestClient(app) as client:
            response = client.get("/multi", headers={"X-API-Key": raw_key})
            assert response.status_code == 200

    @pytest.mark.integration
    async def test_require_scopes_any(
        self, seeded_backend: MemoryBackend, test_api_key: tuple[str, str, APIKeyInfo]
    ) -> None:
        """Test require_scopes with 'any' requirement."""
        raw_key, _, _ = test_api_key

        @get("/any-scope", guards=[require_scopes("read:users", "admin:all", match="any")])
        async def any_scope_route() -> dict:
            return {"access": "granted"}

        app = Litestar(
            route_handlers=[any_scope_route],
            plugins=[
                APIAuthPlugin(
                    config=APIAuthConfig(
                        backend=seeded_backend,
                        auto_routes=False,
                    )
                )
            ],
        )

        with TestClient(app) as client:
            response = client.get("/any-scope", headers={"X-API-Key": raw_key})
            assert response.status_code == 200


class TestCustomHeaderName:
    """Test custom header name configuration."""

    @pytest.mark.integration
    async def test_custom_header_name(
        self, seeded_backend: MemoryBackend, test_api_key: tuple[str, str, APIKeyInfo]
    ) -> None:
        """Test that custom header names work correctly."""
        raw_key, _, _ = test_api_key

        @get("/protected", guards=[require_api_key])
        async def protected_route() -> dict:
            return {"message": "protected"}

        app = Litestar(
            route_handlers=[protected_route],
            plugins=[
                APIAuthPlugin(
                    config=APIAuthConfig(
                        backend=seeded_backend,
                        header_name="Authorization",
                        auto_routes=False,
                    )
                )
            ],
        )

        with TestClient(app) as client:
            # Using custom header
            response = client.get("/protected", headers={"Authorization": raw_key})
            assert response.status_code == 200

            # Using wrong header should fail
            response = client.get("/protected", headers={"X-API-Key": raw_key})
            assert response.status_code == 401


class TestHashImplementationReuse:
    """Regression test: key creation and key verification must hash through
    the canonical ``service.hash_api_key`` instead of each reimplementing
    SHA-256 inline.

    Before the fix, ``APIKeyController.create_api_key`` and
    ``APIKeyMiddleware._hash_api_key`` each called
    ``hashlib.sha256(...).hexdigest()`` directly rather than delegating to
    ``service.hash_api_key``. ``litestar_api_auth.controllers.hash_api_key``
    and ``litestar_api_auth.middleware.hash_api_key`` did not exist to patch,
    so this test would fail with an ``AttributeError`` before the fix.
    """

    @pytest.mark.integration
    async def test_key_created_and_verified_through_patched_canonical_hash(
        self, backend: MemoryBackend, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A change to the canonical hash must be honored by both create and verify."""

        def fake_hash(key: str) -> str:
            # Stand-in for e.g. switching the canonical scheme to a peppered HMAC.
            return "peppered$" + hashlib.sha256(("pepper::" + key).encode()).hexdigest()

        monkeypatch.setattr("litestar_api_auth.controllers.hash_api_key", fake_hash)
        monkeypatch.setattr("litestar_api_auth.middleware.hash_api_key", fake_hash)

        # Seed an admin key hashed under the patched scheme so it can authenticate.
        admin_raw, _ = generate_api_key(prefix="test_")
        admin_hash = fake_hash(admin_raw)
        await backend.create(
            admin_hash,
            APIKeyInfo(
                key_id="admin-key",
                key_hash=admin_hash,
                name="Admin",
                scopes=["api_keys:admin"],
                is_active=True,
            ),
        )

        @get("/protected", guards=[require_api_key])
        async def protected_route() -> dict:
            return {"ok": True}

        app = Litestar(
            route_handlers=[],
            plugins=[
                APIAuthPlugin(
                    config=APIAuthConfig(
                        backend=backend,
                        auto_routes=True,
                        route_handlers=[protected_route],
                    )
                )
            ],
        )

        with TestClient(app) as client:
            # Mint a new key via the controller, authenticating with the
            # admin key that was hashed under the patched scheme.
            create_response = client.post(
                "/api-keys/",
                headers={"X-API-Key": admin_raw},
                json={"name": "new-key", "scopes": ["read:users"]},
            )
            assert create_response.status_code == 201
            new_raw_key = create_response.json()["key"]

            # The controller must have stored the hash under the patched
            # scheme -- not plain SHA-256 -- for the middleware to find it.
            assert await backend.get(fake_hash(new_raw_key)) is not None

            # The middleware must hash the same way to look the key back up.
            response = client.get("/protected", headers={"X-API-Key": new_raw_key})
            assert response.status_code == 200


class TestMultipleInstancesRejected:
    """Regression test: stacking APIAuthPlugin instances must not silently
    cross-wire realms.

    Both middlewares would write to the same ``request.state["api_key"]``
    slot and guards only check scope strings, never which backend validated
    the key -- so a key minted by one realm's backend (e.g. "partner")
    satisfies guards meant for another realm (e.g. "internal") as long as it
    carries the same scope string. On top of that, ``_register_routes``
    unconditionally overwrites the ``"backend"`` dependency, so the
    first-registered realm's auto-registered management controller ends up
    operating on the second realm's backend. Before the fix there was no
    guard against this at all, so a second ``APIAuthPlugin`` instance was
    accepted silently instead of raising.
    """

    def test_second_plugin_instance_raises_configuration_error(self) -> None:
        """A second APIAuthPlugin on one app (with auto-routes on, like the
        real management-controller cross-wiring scenario) must raise, not
        cross-wire realms."""
        internal_backend = MemoryBackend()
        partner_backend = MemoryBackend()

        with pytest.raises(ConfigurationError, match="Multiple APIAuthPlugin"):
            Litestar(
                route_handlers=[],
                plugins=[
                    APIAuthPlugin(config=APIAuthConfig(backend=internal_backend, auto_routes=True)),
                    APIAuthPlugin(config=APIAuthConfig(backend=partner_backend, auto_routes=True)),
                ],
            )

    def test_second_instance_raises_before_mutating_app_config(self) -> None:
        """The check must fire before the second instance touches
        dependencies, routes, or middleware -- so the first instance's
        wiring (in particular the "backend" dependency its management
        controller relies on) is never overwritten, not even transiently."""
        internal_backend = MemoryBackend()
        partner_backend = MemoryBackend()
        first = APIAuthPlugin(config=APIAuthConfig(backend=internal_backend, auto_routes=True))
        second = APIAuthPlugin(config=APIAuthConfig(backend=partner_backend, auto_routes=True))

        app_config = AppConfig(route_handlers=[])
        app_config = first.on_app_init(app_config)

        dependencies_before = dict(app_config.dependencies or {})
        route_handlers_before = list(app_config.route_handlers or [])
        middleware_before = list(app_config.middleware or [])

        with pytest.raises(ConfigurationError, match="Multiple APIAuthPlugin"):
            second.on_app_init(app_config)

        assert app_config.dependencies == dependencies_before
        assert app_config.route_handlers == route_handlers_before
        assert app_config.middleware == middleware_before

    def test_subclass_overriding_backend_dependency_key_is_still_rejected(self) -> None:
        """The single-instance check must not be a per-instance attribute a
        subclass can dodge by renaming ``_backend_dependency_key`` -- that
        subclass would still share the same ``request.state["api_key"]``
        slot and still be vulnerable to the cross-realm scope confusion."""

        class RenamedDependencyKeyPlugin(APIAuthPlugin):
            def __init__(self, config: APIAuthConfig) -> None:
                super().__init__(config)
                self._backend_dependency_key = "partner_api_auth_backend"

        internal_backend = MemoryBackend()
        partner_backend = MemoryBackend()

        with pytest.raises(ConfigurationError, match="Multiple APIAuthPlugin"):
            Litestar(
                route_handlers=[],
                plugins=[
                    APIAuthPlugin(config=APIAuthConfig(backend=internal_backend, auto_routes=False)),
                    RenamedDependencyKeyPlugin(config=APIAuthConfig(backend=partner_backend, auto_routes=False)),
                ],
            )


class _UserStorage:
    """Stand-in for an app owner's own unrelated 'backend', e.g. object storage.

    Defined at module scope (rather than inline in the test) so it resolves
    as a type annotation under this module's ``from __future__ import
    annotations``.
    """


class TestAutoRoutesDoNotClobberAppLevelBackendDependency:
    """Regression test: ``auto_routes`` must not overwrite a user-defined
    app-level ``"backend"`` dependency.

    Before the fix, ``_register_routes`` unconditionally wrote
    ``app_config.dependencies["backend"] = Provide(...)`` pointing at the
    plugin's ``APIKeyBackend`` -- clobbering any app-level ``"backend"``
    dependency the app owner had already defined and injecting the API key
    store into every unrelated handler that happens to declare a ``backend``
    parameter (e.g. a handler meaning to receive its own object storage,
    which could then delete API keys instead of the objects it intended).
    """

    @pytest.mark.integration
    async def test_unrelated_handler_still_receives_its_own_backend_dependency(self, backend: MemoryBackend) -> None:
        """A pre-existing app-level "backend" dependency must reach an
        unrelated handler unchanged, even with auto_routes management
        routes registered."""
        from litestar.di import Provide

        user_storage = _UserStorage()

        @get("/objects", sync_to_thread=False)
        def list_objects(backend: _UserStorage) -> dict[str, bool]:
            return {"is_user_storage": backend is user_storage}

        app = Litestar(
            route_handlers=[list_objects],
            dependencies={"backend": Provide(lambda: user_storage, sync_to_thread=False)},
            plugins=[
                APIAuthPlugin(
                    config=APIAuthConfig(
                        backend=backend,
                        auto_routes=True,
                    )
                )
            ],
        )

        with TestClient(app) as client:
            response = client.get("/objects")

        assert response.status_code == 200
        assert response.json() == {"is_user_storage": True}

    @pytest.mark.integration
    async def test_management_controller_still_uses_its_own_backend_despite_collision(
        self, backend: MemoryBackend
    ) -> None:
        """The auto-registered management controller must keep using the
        plugin's own APIKeyBackend for its own routes, even when the app
        also defines an unrelated app-level "backend" dependency of a
        different type."""
        from litestar.di import Provide

        raw_admin_key, hashed_admin_key = generate_api_key(prefix="test_")
        await backend.create(
            hashed_admin_key,
            APIKeyInfo(
                key_id="admin-key-collision",
                key_hash=hashed_admin_key,
                name="Admin Key",
                scopes=["api_keys:admin"],
                is_active=True,
            ),
        )

        app = Litestar(
            route_handlers=[],
            dependencies={"backend": Provide(lambda: _UserStorage(), sync_to_thread=False)},
            plugins=[
                APIAuthPlugin(
                    config=APIAuthConfig(
                        backend=backend,
                        auto_routes=True,
                    )
                )
            ],
        )

        with TestClient(app) as client:
            response = client.post(
                "/api-keys/",
                headers={"X-API-Key": raw_admin_key},
                json={"name": "new-key", "scopes": ["read:users"]},
            )

        assert response.status_code == 201
