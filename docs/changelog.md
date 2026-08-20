# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Initial project structure
- API key generation with SHA-256 hashing
- Configurable key prefixes
- SQLAlchemy storage backend
- Redis storage backend
- Memory storage backend for testing
- `require_api_key` guard for route protection
- `require_scope` guard for scope-based authorization
- Key expiration support
- Key revocation support
- Last-used tracking
- Auto-registered management routes
- Litestar plugin integration
- Comprehensive documentation

### Changed

- Nothing yet

### Deprecated

- Nothing yet

### Removed

- Nothing yet

### Fixed

- Nothing yet

### Security

- `extract_key_id()` no longer derives its return value from the raw
  characters of the API key's secret portion. It now returns the first 8
  hex characters of the key's SHA-256 hash instead, so following the
  function's own documented advice to log the identifier no longer leaks
  key material. This changes the value `extract_key_id()` returns for
  every existing key - any code that persisted or compared against the
  previous raw-substring output must be updated.

[Unreleased]: https://github.com/JacobCoffee/litestar-api-auth/compare/main...HEAD
