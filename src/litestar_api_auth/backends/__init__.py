"""Storage backends for API key authentication.

This package provides pluggable storage backends following the pattern from
litestar-storages. Each backend implements the APIKeyBackend protocol.

Available backends:
    - MemoryBackend: In-memory storage for testing and development
    - SQLAlchemyBackend: PostgreSQL, MySQL, SQLite via SQLAlchemy
    - RedisBackend: Redis storage for distributed systems

Example:
    ```python
    from litestar_api_auth.backends import MemoryBackend, APIKeyInfo

    # Create backend
    backend = MemoryBackend()

    # Store a key
    info = APIKeyInfo(
        key_id="123e4567-e89b-12d3-a456-426614174000",
        key_hash="hashed_key_value",
        name="Production API Key",
        scopes=["read", "write"],
    )
    await backend.create(info.key_hash, info)

    # Retrieve it
    retrieved = await backend.get(info.key_hash)
    ```
"""

from __future__ import annotations

from litestar_api_auth.backends.base import APIKeyBackend, APIKeyInfo
from litestar_api_auth.backends.memory import MemoryBackend, MemoryConfig

__all__ = (
    # Protocol
    "APIKeyBackend",
    "APIKeyInfo",
    # Memory backend
    "MemoryBackend",
    "MemoryConfig",
    # SQLAlchemy backend
    "APIKeyModel",
    "APIKeyRepository",
    "APIKeyService",
    "SQLAlchemyBackend",
    "SQLAlchemyConfig",
    # Redis backend
    "RedisBackend",
    "RedisConfig",
)


def __getattr__(name: str) -> object:
    """Lazy-load optional backends so missing deps don't cause ImportError.

    This allows ``from litestar_api_auth.backends import MemoryBackend`` to work
    even when ``sqlalchemy`` or ``redis`` are not installed.
    """
    _sqlalchemy_names = {"APIKeyModel", "APIKeyRepository", "APIKeyService", "SQLAlchemyBackend", "SQLAlchemyConfig"}
    _redis_names = {"RedisBackend", "RedisConfig"}

    if name in _sqlalchemy_names:
        from litestar_api_auth.backends import sqlalchemy as _sa

        return getattr(_sa, name)

    if name in _redis_names:
        from litestar_api_auth.backends import redis as _redis

        return getattr(_redis, name)

    msg = f"module {__name__!r} has no attribute {name!r}"
    raise AttributeError(msg)
