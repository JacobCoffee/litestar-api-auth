API Reference
=============

This section provides comprehensive API documentation for all public classes,
functions, and modules in litestar-api-auth.

.. note::
   All storage backends implement the :class:`~litestar_api_auth.backends.base.APIKeyBackend` protocol,
   ensuring consistent behavior across different providers.

Quick Navigation
----------------

**Plugin & Configuration**

* :class:`~litestar_api_auth.plugin.APIAuthPlugin` - Litestar plugin for API key authentication
* :class:`~litestar_api_auth.plugin.APIAuthConfig` - Plugin configuration

**Guards**

* :func:`~litestar_api_auth.guards.require_api_key` - Basic authentication guard
* :func:`~litestar_api_auth.guards.require_scope` - Single scope authorization guard
* :func:`~litestar_api_auth.guards.require_scopes` - Multiple scopes authorization guard
* :func:`~litestar_api_auth.guards.get_api_key_info` - Retrieve API key info from request

**Types**

* :class:`~litestar_api_auth.types.APIKeyInfo` - API key metadata container
* :class:`~litestar_api_auth.types.APIKeyState` - Key state enumeration (active, expired, revoked)

**Schemas (msgspec)**

* :class:`~litestar_api_auth.schemas.CreateAPIKeyRequest` - Key creation request
* :class:`~litestar_api_auth.schemas.UpdateAPIKeyRequest` - Key update request
* :class:`~litestar_api_auth.schemas.APIKeyResponse` - Key response (without raw key)
* :class:`~litestar_api_auth.schemas.APIKeyCreatedResponse` - Key creation response (with raw key)
* :class:`~litestar_api_auth.schemas.APIKeyListResponse` - Paginated key list response

**Storage Backends**

* :class:`~litestar_api_auth.backends.base.APIKeyBackend` - Backend protocol
* :class:`~litestar_api_auth.backends.base.APIKeyInfo` - Backend key info
* :class:`~litestar_api_auth.backends.memory.MemoryBackend` - In-memory (testing/development)
* :class:`~litestar_api_auth.backends.sqlalchemy.SQLAlchemyBackend` - SQLAlchemy backend
* :class:`~litestar_api_auth.backends.sqlalchemy.APIKeyModel` - SQLAlchemy ORM model (Advanced Alchemy)
* :class:`~litestar_api_auth.backends.sqlalchemy.APIKeyRepository` - Async repository (Advanced Alchemy)
* :class:`~litestar_api_auth.backends.sqlalchemy.APIKeyService` - Async service (Advanced Alchemy)
* :class:`~litestar_api_auth.backends.redis.RedisBackend` - Redis backend

**Service Functions**

* :func:`~litestar_api_auth.service.generate_api_key` - Generate a new API key
* :func:`~litestar_api_auth.service.hash_api_key` - Hash an API key for storage
* :func:`~litestar_api_auth.service.verify_api_key` - Verify a key against its hash
* :func:`~litestar_api_auth.service.extract_key_id` - Extract key ID from raw key

**Exceptions**

* :class:`~litestar_api_auth.exceptions.APIAuthError` - Base exception
* :class:`~litestar_api_auth.exceptions.InvalidAPIKeyError` - Invalid key error
* :class:`~litestar_api_auth.exceptions.APIKeyExpiredError` - Expired key error
* :class:`~litestar_api_auth.exceptions.APIKeyRevokedError` - Revoked key error
* :class:`~litestar_api_auth.exceptions.APIKeyNotFoundError` - Key not found error
* :class:`~litestar_api_auth.exceptions.InsufficientScopesError` - Missing scope error
* :class:`~litestar_api_auth.exceptions.ConfigurationError` - Configuration error

**Middleware & Controllers**

* :class:`~litestar_api_auth.middleware.APIKeyMiddleware` - X-API-Key extraction middleware
* :class:`~litestar_api_auth.controllers.APIKeyController` - REST controller for key management
