"""Unit tests for API authentication exceptions."""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from litestar_api_auth.exceptions import (
    APIAuthError,
    APIKeyExpiredError,
    APIKeyNotFoundError,
    APIKeyRevokedError,
    ConfigurationError,
    InsufficientScopesError,
    InvalidAPIKeyError,
)


class TestAPIAuthError:
    """Test suite for base APIAuthError exception."""

    def test_initialization_with_message_only(self) -> None:
        """Test exception initialization with message only."""
        error = APIAuthError("Test error message")

        assert str(error) == "Test error message"
        assert error.message == "Test error message"
        assert error.detail is None

    def test_initialization_with_detail(self) -> None:
        """Test exception initialization with message and detail."""
        detail = {"code": 123, "info": "additional info"}
        error = APIAuthError("Test error", detail=detail)

        assert error.message == "Test error"
        assert error.detail == detail
        assert "detail:" in str(error)
        assert "additional info" in str(error)

    def test_inheritance(self) -> None:
        """Test that APIAuthError inherits from Exception."""
        error = APIAuthError("Test error")

        assert isinstance(error, Exception)


class TestAPIKeyNotFoundError:
    """Test suite for APIKeyNotFoundError exception."""

    def test_initialization_without_key_id(self) -> None:
        """Test exception initialization without key_id."""
        error = APIKeyNotFoundError()

        assert error.message == "API key not found"
        assert error.key_id is None
        assert str(error) == "API key not found"

    def test_initialization_with_key_id(self) -> None:
        """Test exception initialization with key_id."""
        error = APIKeyNotFoundError(key_id="abc123")

        assert error.key_id == "abc123"
        assert "abc123" in str(error)

    def test_initialization_with_detail(self) -> None:
        """Test exception initialization with detail."""
        error = APIKeyNotFoundError(key_id="abc123", detail="Database error")

        assert error.detail == "Database error"
        assert "detail:" in str(error)

    def test_inheritance(self) -> None:
        """Test that APIKeyNotFoundError inherits from APIAuthError."""
        error = APIKeyNotFoundError()

        assert isinstance(error, APIAuthError)
        assert isinstance(error, Exception)


class TestAPIKeyExpiredError:
    """Test suite for APIKeyExpiredError exception."""

    def test_initialization_without_key_id(self) -> None:
        """Test exception initialization without key_id."""
        error = APIKeyExpiredError()

        assert error.message == "API key has expired"
        assert error.key_id is None
        assert error.expired_at is None

    def test_initialization_with_key_id(self) -> None:
        """Test exception initialization with key_id."""
        error = APIKeyExpiredError(key_id="abc123")

        assert error.key_id == "abc123"
        assert "abc123" in str(error)

    def test_initialization_with_expired_at(self) -> None:
        """Test exception initialization with expired_at timestamp."""
        expired_at = datetime.utcnow() - timedelta(days=1)
        error = APIKeyExpiredError(key_id="abc123", expired_at=expired_at)

        assert error.expired_at == expired_at
        assert error.detail == expired_at

    def test_inheritance(self) -> None:
        """Test that APIKeyExpiredError inherits from APIAuthError."""
        error = APIKeyExpiredError()

        assert isinstance(error, APIAuthError)


class TestAPIKeyRevokedError:
    """Test suite for APIKeyRevokedError exception."""

    def test_initialization_without_key_id(self) -> None:
        """Test exception initialization without key_id."""
        error = APIKeyRevokedError()

        assert error.message == "API key has been revoked"
        assert error.key_id is None

    def test_initialization_with_key_id(self) -> None:
        """Test exception initialization with key_id."""
        error = APIKeyRevokedError(key_id="abc123")

        assert error.key_id == "abc123"
        assert "abc123" in str(error)

    def test_inheritance(self) -> None:
        """Test that APIKeyRevokedError inherits from APIAuthError."""
        error = APIKeyRevokedError()

        assert isinstance(error, APIAuthError)


class TestInsufficientScopesError:
    """Test suite for InsufficientScopesError exception."""

    def test_initialization_without_scopes(self) -> None:
        """Test exception initialization without scopes."""
        error = InsufficientScopesError()

        assert error.message == "Insufficient scopes"
        assert error.required_scopes == []
        assert error.provided_scopes == []

    def test_initialization_with_scopes(self) -> None:
        """Test exception initialization with scopes."""
        required = ["admin:write", "admin:delete"]
        provided = ["read:users"]
        error = InsufficientScopesError(
            required_scopes=required,
            provided_scopes=provided,
        )

        assert error.required_scopes == required
        assert error.provided_scopes == provided
        assert "admin:write" in str(error)
        assert "read:users" in str(error)

    def test_inheritance(self) -> None:
        """Test that InsufficientScopesError inherits from APIAuthError."""
        error = InsufficientScopesError()

        assert isinstance(error, APIAuthError)


class TestInvalidAPIKeyError:
    """Test suite for InvalidAPIKeyError exception."""

    def test_initialization_without_reason(self) -> None:
        """Test exception initialization without reason."""
        error = InvalidAPIKeyError()

        assert error.message == "Invalid API key"
        assert error.reason is None

    def test_initialization_with_reason(self) -> None:
        """Test exception initialization with reason."""
        error = InvalidAPIKeyError(reason="Invalid key format")

        assert error.reason == "Invalid key format"
        assert "Invalid key format" in str(error)

    def test_inheritance(self) -> None:
        """Test that InvalidAPIKeyError inherits from APIAuthError."""
        error = InvalidAPIKeyError()

        assert isinstance(error, APIAuthError)


class TestConfigurationError:
    """Test suite for ConfigurationError exception."""

    def test_initialization(self) -> None:
        """Test exception initialization."""
        error = ConfigurationError("Missing required setting")

        assert error.message == "Missing required setting"
        assert str(error) == "Missing required setting"

    def test_initialization_with_detail(self) -> None:
        """Test exception initialization with detail."""
        error = ConfigurationError(
            "Missing required setting",
            detail={"setting": "backend"},
        )

        assert error.detail == {"setting": "backend"}
        assert "detail:" in str(error)

    def test_inheritance(self) -> None:
        """Test that ConfigurationError inherits from APIAuthError."""
        error = ConfigurationError("Test error")

        assert isinstance(error, APIAuthError)


class TestExceptionRaising:
    """Test suite for raising and catching exceptions."""

    def test_catch_base_exception(self) -> None:
        """Test catching specific exception as base type."""
        with pytest.raises(APIAuthError):
            raise APIKeyNotFoundError(key_id="abc123")

    def test_catch_specific_exception(self) -> None:
        """Test catching specific exception type."""
        with pytest.raises(APIKeyNotFoundError) as exc_info:
            raise APIKeyNotFoundError(key_id="abc123")

        assert exc_info.value.key_id == "abc123"

    def test_exception_context_manager(self) -> None:
        """Test using exception in context manager."""
        with pytest.raises(InsufficientScopesError) as exc_info:
            raise InsufficientScopesError(
                required_scopes=["admin:write"],
                provided_scopes=["read:users"],
            )

        error = exc_info.value
        assert "admin:write" in error.required_scopes
        assert "read:users" in error.provided_scopes
