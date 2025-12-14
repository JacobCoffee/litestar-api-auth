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

from litestar_api_auth.backends.base import APIKeyBackend, APIKeyInfo
from litestar_api_auth.backends.memory import MemoryBackend, MemoryConfig
from litestar_api_auth.backends.redis import RedisBackend, RedisConfig
from litestar_api_auth.backends.sqlalchemy import SQLAlchemyBackend, SQLAlchemyConfig

__all__ = (
    # Protocol
    "APIKeyBackend",
    "APIKeyInfo",
    # Memory backend
    "MemoryBackend",
    "MemoryConfig",
    # SQLAlchemy backend
    "SQLAlchemyBackend",
    "SQLAlchemyConfig",
    # Redis backend
    "RedisBackend",
    "RedisConfig",
)
