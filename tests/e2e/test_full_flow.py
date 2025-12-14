"""End-to-end tests for the complete API key authentication flow.

These tests verify the entire workflow from key generation to authentication
to accessing protected resources, simulating real-world usage scenarios.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from litestar import Litestar, Request, get
from litestar.testing import TestClient

from litestar_api_auth import APIAuthConfig, APIAuthPlugin, require_api_key
from litestar_api_auth.backends.base import APIKeyInfo
from litestar_api_auth.backends.memory import MemoryBackend
from litestar_api_auth.guards import get_api_key_info, require_scope
from litestar_api_auth.service import generate_api_key


class TestFullAuthenticationFlow:
    """Test complete authentication workflows end-to-end."""

    @pytest.mark.e2e
    async def test_create_key_authenticate_access_resource(self) -> None:
        """Test the complete flow: create key -> authenticate -> access resource."""
        backend = MemoryBackend()

        @get("/protected", guards=[require_api_key])
        async def protected_resource() -> dict:
            return {"data": "secret information"}

        app = Litestar(
            route_handlers=[protected_resource],
            plugins=[
                APIAuthPlugin(
                    config=APIAuthConfig(
                        backend=backend,
                        auto_routes=False,
                    )
                )
            ],
        )

        # Step 1: Generate an API key
        raw_key, hashed_key = generate_api_key(prefix="app_")

        # Step 2: Store the key in the backend
        key_info = APIKeyInfo(
            key_id="user-123-key",
            key_hash=hashed_key,
            name="User 123 API Key",
            scopes=["read:data"],
            is_active=True,
        )
        await backend.create(hashed_key, key_info)

        # Step 3: Use the key to access protected resource
        with TestClient(app) as client:
            response = client.get("/protected", headers={"X-API-Key": raw_key})
            assert response.status_code == 200
            assert response.json() == {"data": "secret information"}

    @pytest.mark.e2e
    async def test_key_revocation_denies_access(self) -> None:
        """Test that revoking a key immediately denies access."""
        backend = MemoryBackend()

        @get("/protected", guards=[require_api_key])
        async def protected_resource() -> dict:
            return {"data": "secret"}

        app = Litestar(
            route_handlers=[protected_resource],
            plugins=[
                APIAuthPlugin(
                    config=APIAuthConfig(
                        backend=backend,
                        auto_routes=False,
                    )
                )
            ],
        )

        # Create and store a key
        raw_key, hashed_key = generate_api_key(prefix="app_")
        key_info = APIKeyInfo(
            key_id="revoke-test-key",
            key_hash=hashed_key,
            name="Revoke Test Key",
            scopes=["read:data"],
            is_active=True,
        )
        await backend.create(hashed_key, key_info)

        with TestClient(app) as client:
            # Key works initially
            response = client.get("/protected", headers={"X-API-Key": raw_key})
            assert response.status_code == 200

            # Revoke the key
            await backend.revoke(hashed_key)

            # Key should no longer work
            response = client.get("/protected", headers={"X-API-Key": raw_key})
            assert response.status_code == 401

    @pytest.mark.e2e
    async def test_expired_key_denies_access(self) -> None:
        """Test that expired keys are rejected."""
        backend = MemoryBackend()

        @get("/protected", guards=[require_api_key])
        async def protected_resource() -> dict:
            return {"data": "secret"}

        app = Litestar(
            route_handlers=[protected_resource],
            plugins=[
                APIAuthPlugin(
                    config=APIAuthConfig(
                        backend=backend,
                        auto_routes=False,
                    )
                )
            ],
        )

        # Create an already-expired key
        raw_key, hashed_key = generate_api_key(prefix="app_")
        key_info = APIKeyInfo(
            key_id="expired-test-key",
            key_hash=hashed_key,
            name="Expired Test Key",
            scopes=["read:data"],
            is_active=True,
            expires_at=datetime.now(timezone.utc) - timedelta(hours=1),  # Expired 1 hour ago
        )
        await backend.create(hashed_key, key_info)

        with TestClient(app) as client:
            response = client.get("/protected", headers={"X-API-Key": raw_key})
            assert response.status_code == 401

    @pytest.mark.e2e
    async def test_scope_based_access_control(self) -> None:
        """Test that scope-based access control works correctly."""
        backend = MemoryBackend()

        @get("/users", guards=[require_scope("read:users")])
        async def read_users() -> dict:
            return {"users": ["alice", "bob"]}

        @get("/admin", guards=[require_scope("admin:all")])
        async def admin_panel() -> dict:
            return {"admin": True}

        app = Litestar(
            route_handlers=[read_users, admin_panel],
            plugins=[
                APIAuthPlugin(
                    config=APIAuthConfig(
                        backend=backend,
                        auto_routes=False,
                    )
                )
            ],
        )

        # Create a key with limited scopes
        raw_key, hashed_key = generate_api_key(prefix="app_")
        key_info = APIKeyInfo(
            key_id="limited-scope-key",
            key_hash=hashed_key,
            name="Limited Scope Key",
            scopes=["read:users"],  # Only has read:users, not admin:all
            is_active=True,
        )
        await backend.create(hashed_key, key_info)

        with TestClient(app) as client:
            # Can access read:users endpoint
            response = client.get("/users", headers={"X-API-Key": raw_key})
            assert response.status_code == 200

            # Cannot access admin:all endpoint
            response = client.get("/admin", headers={"X-API-Key": raw_key})
            assert response.status_code == 403

    @pytest.mark.e2e
    async def test_access_key_info_in_handler(self) -> None:
        """Test that handlers can access the authenticated key info."""
        backend = MemoryBackend()

        @get("/me", guards=[require_api_key])
        async def get_current_key(request: Request) -> dict:
            key_info = get_api_key_info(request)
            return {
                "key_id": key_info.key_id,
                "name": key_info.name,
                "scopes": key_info.scopes,
            }

        app = Litestar(
            route_handlers=[get_current_key],
            plugins=[
                APIAuthPlugin(
                    config=APIAuthConfig(
                        backend=backend,
                        auto_routes=False,
                    )
                )
            ],
        )

        # Create a key
        raw_key, hashed_key = generate_api_key(prefix="app_")
        key_info = APIKeyInfo(
            key_id="info-test-key",
            key_hash=hashed_key,
            name="Info Test Key",
            scopes=["read:self"],
            is_active=True,
        )
        await backend.create(hashed_key, key_info)

        with TestClient(app) as client:
            response = client.get("/me", headers={"X-API-Key": raw_key})
            assert response.status_code == 200
            data = response.json()
            assert data["key_id"] == "info-test-key"
            assert data["name"] == "Info Test Key"
            assert data["scopes"] == ["read:self"]

    @pytest.mark.e2e
    async def test_multiple_keys_for_same_user(self) -> None:
        """Test that multiple API keys can coexist and work independently."""
        backend = MemoryBackend()

        @get("/protected", guards=[require_api_key])
        async def protected_resource(request: Request) -> dict:
            key_info = get_api_key_info(request)
            return {"authenticated_with": key_info.name}

        app = Litestar(
            route_handlers=[protected_resource],
            plugins=[
                APIAuthPlugin(
                    config=APIAuthConfig(
                        backend=backend,
                        auto_routes=False,
                    )
                )
            ],
        )

        # Create two keys
        raw_key_1, hashed_key_1 = generate_api_key(prefix="app_")
        raw_key_2, hashed_key_2 = generate_api_key(prefix="app_")

        key_info_1 = APIKeyInfo(
            key_id="key-1",
            key_hash=hashed_key_1,
            name="Production Key",
            scopes=["read:data"],
            is_active=True,
        )
        key_info_2 = APIKeyInfo(
            key_id="key-2",
            key_hash=hashed_key_2,
            name="Development Key",
            scopes=["read:data"],
            is_active=True,
        )

        await backend.create(hashed_key_1, key_info_1)
        await backend.create(hashed_key_2, key_info_2)

        with TestClient(app) as client:
            # Both keys should work independently
            response = client.get("/protected", headers={"X-API-Key": raw_key_1})
            assert response.status_code == 200
            assert response.json()["authenticated_with"] == "Production Key"

            response = client.get("/protected", headers={"X-API-Key": raw_key_2})
            assert response.status_code == 200
            assert response.json()["authenticated_with"] == "Development Key"

    @pytest.mark.e2e
    async def test_last_used_tracking(self) -> None:
        """Test that last_used_at is updated when keys are used."""
        backend = MemoryBackend()

        @get("/protected", guards=[require_api_key])
        async def protected_resource() -> dict:
            return {"data": "secret"}

        app = Litestar(
            route_handlers=[protected_resource],
            plugins=[
                APIAuthPlugin(
                    config=APIAuthConfig(
                        backend=backend,
                        track_usage=True,
                        auto_routes=False,
                    )
                )
            ],
        )

        # Create a key without last_used_at
        raw_key, hashed_key = generate_api_key(prefix="app_")
        key_info = APIKeyInfo(
            key_id="tracking-test-key",
            key_hash=hashed_key,
            name="Tracking Test Key",
            scopes=["read:data"],
            is_active=True,
            last_used_at=None,  # Never used
        )
        await backend.create(hashed_key, key_info)

        # Verify last_used_at is None initially
        stored_key = await backend.get(hashed_key)
        assert stored_key is not None
        assert stored_key.last_used_at is None

        with TestClient(app) as client:
            response = client.get("/protected", headers={"X-API-Key": raw_key})
            assert response.status_code == 200

            # Verify last_used_at was updated (must check inside context before backend.close())
            stored_key = await backend.get(hashed_key)
            assert stored_key is not None
            assert stored_key.last_used_at is not None


class TestErrorScenarios:
    """Test error handling in various scenarios."""

    @pytest.mark.e2e
    async def test_malformed_api_key(self) -> None:
        """Test that malformed API keys are handled gracefully."""
        backend = MemoryBackend()

        @get("/protected", guards=[require_api_key])
        async def protected_resource() -> dict:
            return {"data": "secret"}

        app = Litestar(
            route_handlers=[protected_resource],
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
            # Empty key
            response = client.get("/protected", headers={"X-API-Key": ""})
            assert response.status_code == 401

            # Whitespace only
            response = client.get("/protected", headers={"X-API-Key": "   "})
            assert response.status_code == 401

            # Random string (not a valid key format)
            response = client.get("/protected", headers={"X-API-Key": "not-a-valid-key"})
            assert response.status_code == 401

    @pytest.mark.e2e
    async def test_deleted_key_denies_access(self) -> None:
        """Test that deleted keys are rejected."""
        backend = MemoryBackend()

        @get("/protected", guards=[require_api_key])
        async def protected_resource() -> dict:
            return {"data": "secret"}

        app = Litestar(
            route_handlers=[protected_resource],
            plugins=[
                APIAuthPlugin(
                    config=APIAuthConfig(
                        backend=backend,
                        auto_routes=False,
                    )
                )
            ],
        )

        # Create and store a key
        raw_key, hashed_key = generate_api_key(prefix="app_")
        key_info = APIKeyInfo(
            key_id="delete-test-key",
            key_hash=hashed_key,
            name="Delete Test Key",
            scopes=["read:data"],
            is_active=True,
        )
        await backend.create(hashed_key, key_info)

        with TestClient(app) as client:
            # Key works initially
            response = client.get("/protected", headers={"X-API-Key": raw_key})
            assert response.status_code == 200

            # Delete the key
            await backend.delete(hashed_key)

            # Key should no longer work
            response = client.get("/protected", headers={"X-API-Key": raw_key})
            assert response.status_code == 401
