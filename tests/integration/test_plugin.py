"""Integration tests for the APIAuthPlugin with Litestar TestClient.

These tests verify that the plugin correctly integrates with Litestar
applications, including middleware, guards, and dependency injection.
"""

from __future__ import annotations

import pytest
from litestar import Litestar, get
from litestar.testing import TestClient

from litestar_api_auth import APIAuthConfig, APIAuthPlugin, require_api_key
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
