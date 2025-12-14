"""Exception hierarchy for API key authentication.

This module defines a comprehensive exception hierarchy for handling
various error conditions in the API key authentication system.
"""

from __future__ import annotations

from typing import Any

__all__ = [
    "APIAuthError",
    "APIKeyNotFoundError",
    "APIKeyExpiredError",
    "APIKeyRevokedError",
    "InsufficientScopesError",
    "InvalidAPIKeyError",
    "ConfigurationError",
]


class APIAuthError(Exception):
    """Base exception for all API authentication errors.

    This is the root exception class that all other API authentication
    exceptions inherit from. Catching this exception will catch all
    authentication-related errors.

    Attributes:
        message: A description of the error.
        detail: Optional additional details about the error.

    Example:
        >>> try:
        ...     raise APIAuthError("Authentication failed")
        ... except APIAuthError as e:
        ...     print(f"Error: {e}")
        Error: Authentication failed
    """

    def __init__(self, message: str, detail: Any | None = None) -> None:
        """Initialize the exception.

        Args:
            message: A description of the error.
            detail: Optional additional details about the error.
        """
        self.message = message
        self.detail = detail
        super().__init__(message)

    def __str__(self) -> str:
        """Return a string representation of the exception.

        Returns:
            The error message, optionally with detail information.
        """
        if self.detail is not None:
            return f"{self.message} (detail: {self.detail})"
        return self.message


class APIKeyNotFoundError(APIAuthError):
    """Raised when an API key cannot be found in the backend.

    This exception is raised when attempting to retrieve or validate
    an API key that does not exist in the storage backend.

    Example:
        >>> raise APIKeyNotFoundError(key_id="abc123")
        Traceback (most recent call last):
        ...
        APIKeyNotFoundError: API key not found
    """

    def __init__(self, key_id: str | None = None, detail: Any | None = None) -> None:
        """Initialize the exception.

        Args:
            key_id: Optional key identifier that was not found.
            detail: Optional additional details about the error.
        """
        message = "API key not found"
        if key_id:
            message = f"API key not found: {key_id}"
        super().__init__(message=message, detail=detail)
        self.key_id = key_id


class APIKeyExpiredError(APIAuthError):
    """Raised when an API key has expired.

    This exception is raised when attempting to use an API key that
    has passed its expiration date.

    Example:
        >>> from datetime import datetime, timedelta
        >>> expired_at = datetime.utcnow() - timedelta(days=1)
        >>> raise APIKeyExpiredError(key_id="abc123", expired_at=expired_at)
        Traceback (most recent call last):
        ...
        APIKeyExpiredError: API key has expired
    """

    def __init__(
        self,
        key_id: str | None = None,
        expired_at: Any | None = None,
        detail: Any | None = None,
    ) -> None:
        """Initialize the exception.

        Args:
            key_id: Optional key identifier that expired.
            expired_at: Optional timestamp when the key expired.
            detail: Optional additional details about the error.
        """
        message = "API key has expired"
        if key_id:
            message = f"API key has expired: {key_id}"
        super().__init__(message=message, detail=detail or expired_at)
        self.key_id = key_id
        self.expired_at = expired_at


class APIKeyRevokedError(APIAuthError):
    """Raised when an API key has been revoked.

    This exception is raised when attempting to use an API key that
    has been manually revoked and is no longer active.

    Example:
        >>> raise APIKeyRevokedError(key_id="abc123")
        Traceback (most recent call last):
        ...
        APIKeyRevokedError: API key has been revoked
    """

    def __init__(self, key_id: str | None = None, detail: Any | None = None) -> None:
        """Initialize the exception.

        Args:
            key_id: Optional key identifier that was revoked.
            detail: Optional additional details about the error.
        """
        message = "API key has been revoked"
        if key_id:
            message = f"API key has been revoked: {key_id}"
        super().__init__(message=message, detail=detail)
        self.key_id = key_id


class InsufficientScopesError(APIAuthError):
    """Raised when an API key lacks required scopes/permissions.

    This exception is raised when an API key is valid but does not
    have the necessary scopes to access a protected resource.

    Example:
        >>> raise InsufficientScopesError(
        ...     required_scopes=["admin:write"],
        ...     provided_scopes=["read:users"],
        ... )
        Traceback (most recent call last):
        ...
        InsufficientScopesError: Insufficient scopes. Required: ['admin:write'], provided: ['read:users']
    """

    def __init__(
        self,
        required_scopes: list[str] | None = None,
        provided_scopes: list[str] | None = None,
        detail: Any | None = None,
    ) -> None:
        """Initialize the exception.

        Args:
            required_scopes: List of scopes that were required.
            provided_scopes: List of scopes that were provided.
            detail: Optional additional details about the error.
        """
        message = "Insufficient scopes"
        if required_scopes or provided_scopes:
            message = f"Insufficient scopes. Required: {required_scopes or []}, provided: {provided_scopes or []}"
        super().__init__(message=message, detail=detail)
        self.required_scopes = required_scopes or []
        self.provided_scopes = provided_scopes or []


class InvalidAPIKeyError(APIAuthError):
    """Raised when an API key is malformed or invalid.

    This exception is raised when an API key has an invalid format,
    fails verification, or is otherwise malformed.

    Example:
        >>> raise InvalidAPIKeyError(reason="Invalid key format")
        Traceback (most recent call last):
        ...
        InvalidAPIKeyError: Invalid API key: Invalid key format
    """

    def __init__(self, reason: str | None = None, detail: Any | None = None) -> None:
        """Initialize the exception.

        Args:
            reason: Optional reason why the key is invalid.
            detail: Optional additional details about the error.
        """
        message = "Invalid API key"
        if reason:
            message = f"Invalid API key: {reason}"
        super().__init__(message=message, detail=detail)
        self.reason = reason


class ConfigurationError(APIAuthError):
    """Raised when there is a configuration error.

    This exception is raised when the API authentication plugin
    or backend is misconfigured.

    Example:
        >>> raise ConfigurationError("Missing required backend configuration")
        Traceback (most recent call last):
        ...
        ConfigurationError: Missing required backend configuration
    """

    def __init__(self, message: str, detail: Any | None = None) -> None:
        """Initialize the exception.

        Args:
            message: Description of the configuration error.
            detail: Optional additional details about the error.
        """
        super().__init__(message=message, detail=detail)
