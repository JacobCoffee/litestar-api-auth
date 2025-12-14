"""Pytest configuration and shared fixtures for litestar-api-auth tests.

This module provides reusable fixtures for testing API key authentication
functionality across the test suite.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from litestar_api_auth.backends.memory import MemoryBackend, MemoryConfig
from litestar_api_auth.service import generate_api_key
from litestar_api_auth.types import APIKeyInfo


@pytest.fixture
def memory_backend() -> MemoryBackend:
    """Provide a fresh in-memory backend for testing.

    Returns:
        A new MemoryBackend instance with empty storage.
    """
    return MemoryBackend(MemoryConfig())


@pytest.fixture
def api_key_pair() -> tuple[str, str]:
    """Generate a test API key pair.

    Returns:
        A tuple of (raw_key, hashed_key) with default "test_" prefix.
    """
    return generate_api_key("test_")


@pytest.fixture
def custom_api_key_pair() -> tuple[str, str]:
    """Generate a test API key pair with custom prefix.

    Returns:
        A tuple of (raw_key, hashed_key) with "custom_" prefix.
    """
    return generate_api_key("custom_")


@pytest.fixture
def sample_api_key_info() -> APIKeyInfo:
    """Provide sample API key metadata for testing types.py.

    Returns:
        An APIKeyInfo instance with typical test data (from types.py).
    """
    now = datetime.now(timezone.utc)
    return APIKeyInfo(
        key_id="test-key-id-123",
        prefix="test_",
        name="Test API Key",
        scopes=["read:users", "write:posts"],
        is_active=True,
        created_at=now,
        expires_at=now + timedelta(days=30),
        last_used_at=None,
        metadata={"owner": "test@example.com"},
    )


@pytest.fixture
def expired_api_key_info() -> APIKeyInfo:
    """Provide an expired API key for testing.

    Returns:
        An APIKeyInfo instance that has already expired.
    """
    now = datetime.now(timezone.utc)
    return APIKeyInfo(
        key_id="expired-key-id-456",
        prefix="test_",
        name="Expired API Key",
        scopes=["read:users"],
        is_active=True,
        created_at=now - timedelta(days=60),
        expires_at=now - timedelta(days=1),  # Expired yesterday
        last_used_at=now - timedelta(days=2),
        metadata={},
    )


@pytest.fixture
def revoked_api_key_info() -> APIKeyInfo:
    """Provide a revoked API key for testing.

    Returns:
        An APIKeyInfo instance that has been revoked (is_active=False).
    """
    now = datetime.now(timezone.utc)
    return APIKeyInfo(
        key_id="revoked-key-id-789",
        prefix="test_",
        name="Revoked API Key",
        scopes=["admin:all"],
        is_active=False,  # Revoked
        created_at=now - timedelta(days=30),
        expires_at=None,
        last_used_at=now - timedelta(days=5),
        metadata={"revoked_by": "admin@example.com"},
    )
