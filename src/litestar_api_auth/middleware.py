"""Middleware for API key extraction and validation.

This module provides ASGI middleware for extracting API keys from request headers,
validating them against a backend storage, and storing the key information in
request state for use by guards.
"""

from __future__ import annotations

import contextlib
from typing import TYPE_CHECKING, Protocol

import msgspec
from litestar.middleware import AbstractMiddleware

from litestar_api_auth.backends.base import APIKeyInfo
from litestar_api_auth.exceptions import (
    APIKeyExpiredError,
    APIKeyNotFoundError,
    APIKeyRevokedError,
    InvalidAPIKeyError,
)
from litestar_api_auth.service import hash_api_key

if TYPE_CHECKING:
    from litestar.types import ASGIApp, Receive, Scope, Send

__all__ = [
    "APIKeyBackend",
    "APIKeyMiddleware",
]


class APIKeyBackend(Protocol):
    """Protocol defining the interface for API key storage backends.

    Any backend implementation must provide these methods to be compatible
    with the middleware.
    """

    async def get(self, key_hash: str) -> APIKeyInfo | None:
        """Retrieve API key information by its hash.

        Args:
            key_hash: The hashed API key value.

        Returns:
            APIKeyInfo if the key exists, None otherwise.
        """
        ...

    async def update_last_used(self, key_hash: str) -> APIKeyInfo | None:
        """Update the last used timestamp for an API key.

        Returning the freshly written record when the key still exists lets
        ``APIKeyMiddleware`` detect a revoke() (or an expiry shortened by a
        concurrent update()) that landed in the narrow window between its
        earlier ``get()`` call and this one -- see the "Revocation timing"
        section of ``APIKeyMiddleware``'s docstring. Returning ``None`` is
        ambiguous by design: it covers both "nothing further to report" (a
        backend that predates this return value) *and* "the key was deleted
        concurrently" -- the middleware cannot tell those apart, so a
        concurrent delete() in that same window is not caught this way.

        Args:
            key_hash: The hashed API key value.

        Returns:
            The updated APIKeyInfo if the backend can provide one, None otherwise.
        """
        ...


class APIKeyMiddleware(AbstractMiddleware):
    """ASGI middleware for API key extraction and validation.

    This middleware extracts API keys from request headers, validates them
    against a backend storage, and stores the key information in request state.

    The middleware performs the following steps:
    1. Extracts the API key from the configured header (default: X-API-Key)
    2. Hashes the key and looks it up in the backend
    3. Validates that the key is active and not expired
    4. Stores the APIKeyInfo in request.state.api_key
    5. Updates the last_used_at timestamp

    Guards can then check request.state.api_key to enforce authentication
    and authorization policies.

    Revocation timing:
        Guards check the ``APIKeyInfo`` snapshot this middleware captured
        from a single ``backend.get()`` call, not the backend itself.
        ``is_active``, ``scopes``, and ``expires_at`` are all values copied
        from that one call and are never re-fetched for the rest of the
        request: only the *comparison* against ``expires_at`` is re-evaluated
        live (against the current wall-clock time) on every guard check, not
        ``expires_at`` itself. So if a key is revoked, has a scope removed, or
        has its expiry shortened *after* this middleware's ``backend.get()``
        call but before the guard/handler for *that same request* finishes
        running, that one in-flight request is unaffected by the change --
        it keeps evaluating against the pre-change snapshot for its entire
        lifetime. This is standard request-scoped caching, not a reusable
        bypass: every request validated *after* the backend change lands
        sees it, since that request's own ``backend.get()`` call returns the
        updated record.

        The one exception is the narrower window between that ``backend.get()``
        call and the ``update_last_used()`` call made moments later, still
        within the same request: if a backend's ``update_last_used()`` returns
        its freshly written record (the bundled memory/Redis/SQLAlchemy
        backends all do, whenever the key still exists), this middleware
        re-validates it and rejects the request if a revoke() or an expiry
        shortened by a concurrent update() landed in that window, instead of
        installing the now-stale ``backend.get()`` snapshot. A backend that
        returns ``None`` from ``update_last_used()`` is unaffected either way
        -- the request proceeds on the original snapshot exactly as before --
        and that includes the case where the key was *deleted* concurrently
        in that same window: a bundled backend's ``update_last_used()`` also
        returns ``None`` then (it cannot distinguish "deleted" from "nothing
        to report" without breaking backends that predate this return value),
        so a concurrent delete() in this narrow window is not caught.

    Attributes:
        backend: The storage backend for API keys.
        header_name: The HTTP header name to extract the key from.
        update_last_used: Whether to update the last_used_at timestamp on each request.

    Example:
        >>> from litestar import Litestar
        >>> from litestar_api_auth.middleware import APIKeyMiddleware
        >>> from litestar_api_auth.backends.memory import MemoryBackend
        >>>
        >>> backend = MemoryBackend()
        >>> app = Litestar(
        ...     route_handlers=[...],
        ...     middleware=[APIKeyMiddleware(backend=backend)],
        ... )
    """

    def __init__(
        self,
        app: ASGIApp,
        backend: APIKeyBackend,
        header_name: str = "X-API-Key",
        update_last_used: bool = True,
        exclude_paths: str | list[str] | None = None,
    ) -> None:
        """Initialize the middleware.

        Args:
            app: The ASGI application.
            backend: The storage backend for API keys.
            header_name: The HTTP header name to extract the key from. Defaults to "X-API-Key".
            update_last_used: Whether to update the last_used_at timestamp. Defaults to True.
            exclude_paths: Regex pattern or list of regex patterns matched
                (unanchored) against the request path. Matching requests
                bypass this middleware entirely (see
                ``AbstractMiddleware.exclude``), so no lookup or usage-update
                is performed for them even if an API key header is present.
        """
        super().__init__(app=app, exclude=exclude_paths)
        self.backend = backend
        self.header_name = header_name.lower()  # HTTP headers are case-insensitive
        self.update_last_used = update_last_used

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Process the request through the middleware.

        Args:
            scope: The ASGI connection scope.
            receive: The ASGI receive channel.
            send: The ASGI send channel.
        """
        if "state" not in scope:
            scope["state"] = {}

        # Clear any pre-existing/stale state["api_key"] up front so a value
        # left over from another middleware (or a prior request) can never
        # be trusted as authenticated unless this middleware validates a key
        # on *this* request. This must happen before the HTTP-only check
        # below, since AbstractMiddleware also routes WebSocket scopes here.
        scope["state"]["api_key"] = None

        # Only process HTTP requests -- this middleware does not authenticate
        # WebSocket connections, but stale state has already been cleared above.
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Extract API key from headers
        api_key = self._extract_api_key(scope)

        # If an API key is present, validate it and store in state. key_info
        # starts as a snapshot as of this backend.get() call (see
        # "Revocation timing" in the class docstring): once state["api_key"]
        # below is populated from it, a revoke()/scope change that lands
        # afterward does not retroactively affect this in-flight request's
        # snapshot. A backend can still catch a concurrent revocation in the
        # narrower window up to update_last_used() -- see the comment there --
        # in which case key_info is replaced with that fresher record first.
        if api_key:
            try:
                key_info = await self._validate_api_key(api_key)

                # Update last used timestamp if enabled. This stays inside the
                # same try as validation -- and state["api_key"] is only ever
                # populated in the `else` clause below -- so a race-aware
                # custom backend raising APIKeyNotFoundError/APIKeyExpiredError/
                # APIKeyRevokedError/InvalidAPIKeyError here (e.g. detecting a
                # concurrent revocation or deletion), or _check_key_info_is_valid()
                # raising one of those same errors against a fresher record the
                # backend returns instead, is handled the same way a validation
                # failure is -- instead of leaving a just-invalidated key
                # authenticated because state was already set beforehand.
                if self.update_last_used:
                    key_hash = self._hash_api_key(api_key)
                    with contextlib.suppress(RuntimeError):
                        # Usage tracking is best-effort: a backend that raises
                        # RuntimeError here (e.g. Redis exhausting its
                        # WATCH/MULTI retries under heavy write contention on
                        # this key) must not turn an otherwise valid,
                        # already-authenticated request into a failure.
                        updated_info = await self.backend.update_last_used(key_hash)

                        # A backend that returns its freshly written record
                        # here (the bundled memory/Redis/SQLAlchemy backends
                        # all do, when the key still exists) lets us catch a
                        # revoke() or an expiry shortened by a concurrent
                        # update() that committed in the narrow window between
                        # backend.get() above and this call -- closing the
                        # race for backends that support it instead of
                        # installing the by-then-stale key_info snapshot. A
                        # backend that returns None here -- either because it
                        # predates this return value, or because (for the
                        # bundled backends) the key was deleted concurrently,
                        # which is indistinguishable from the former -- leaves
                        # key_info, and thus the request, exactly as before.
                        if updated_info is not None:
                            self._check_key_info_is_valid(updated_info)
                            key_info = updated_info
            except (
                APIKeyNotFoundError,
                APIKeyExpiredError,
                APIKeyRevokedError,
                InvalidAPIKeyError,
            ):
                # state["api_key"] stays None (cleared above) if validation
                # (or a race-aware update_last_used()) fails.
                # Guards will handle the missing key appropriately
                pass
            except BaseException:
                # An *unexpected* error (a backend bug/outage, not one of the
                # known validation-failure types above) is about to propagate
                # out of this frame while it still holds the raw api_key (and
                # possibly key_hash/key_info). Scrub them first so a
                # monitoring tool that captures frame locals on unhandled
                # exceptions (e.g. Sentry's include_local_variables) cannot
                # recover them from this frame's traceback entry.
                api_key = key_hash = key_info = updated_info = None
                raise
            else:
                # Store the APIKeyInfo in request state for guards to access.
                # key_hash is redacted first: it's the SHA-256 verifier used
                # for backend lookups only, and a route handler that returns
                # this object directly (see the Warning in
                # guards.get_api_key_info's docstring) would otherwise
                # serialize the hash into the HTTP response.
                try:
                    redacted_key_info = msgspec.structs.replace(key_info, key_hash="")
                except BaseException:
                    # An exception raised here (e.g. a custom backend's
                    # key_info duck-typing its way past
                    # _check_key_info_is_valid without actually being a
                    # msgspec.Struct, so replace() raises TypeError) is
                    # *not* caught by the `except BaseException` above --
                    # exceptions raised in an `else` clause are not handled
                    # by the `except` clauses of that same try statement --
                    # so this needs its own scrub-and-reraise before it
                    # propagates out of this frame while api_key is still
                    # the raw bearer key.
                    api_key = key_hash = key_info = updated_info = None
                    raise
                scope["state"]["api_key"] = redacted_key_info

        # None of api_key/key_hash/key_info are needed past this point (the
        # key has already been hashed and, if valid, handed off via
        # scope["state"]["api_key"] above as a key_hash-redacted copy).
        # Clear them from this frame before awaiting the downstream app so
        # they can't be recovered from this frame's locals if a monitoring
        # tool captures them on an unhandled downstream exception (e.g.
        # Sentry's include_local_variables). This cannot, however, scrub the
        # raw header value out of scope["headers"] itself -- ASGI requires
        # the original headers to remain available to downstream
        # middleware/handlers, so a frame-locals capture of the *downstream*
        # app's own frame can still observe the raw key via scope.
        api_key = key_hash = key_info = updated_info = None

        # Continue processing the request
        await self.app(scope, receive, send)

    def _extract_api_key(self, scope: Scope) -> str | None:
        """Extract the API key from request headers.

        Args:
            scope: The ASGI connection scope.

        Returns:
            The API key value if present, None otherwise.
        """
        headers = scope.get("headers", [])

        for header_name, header_value in headers:
            if header_name.decode("latin-1").lower() == self.header_name:
                return header_value.decode("latin-1").strip()

        return None

    async def _validate_api_key(self, api_key: str) -> APIKeyInfo:
        """Validate an API key against the backend.

        Args:
            api_key: The raw API key value from the request.

        Returns:
            The validated APIKeyInfo.

        Raises:
            APIKeyNotFoundError: If the key is not found in the backend.
            APIKeyExpiredError: If the key has expired.
            APIKeyRevokedError: If the key has been revoked.
            InvalidAPIKeyError: If the key format is invalid.
        """
        # Hash the API key (backends store hashes, not plaintext), then drop
        # the raw value immediately -- it is never read again in this
        # function, and leaving it bound as a frame local would let a
        # monitoring tool that captures frame locals on any exception below
        # (backend.get() raising unexpectedly, or key_info.is_active/
        # is_expired raising) recover the plaintext bearer key from this
        # frame's traceback entry. __call__'s own BaseException handler only
        # scrubs its *own* frame, not this one. _hash_api_key() itself is
        # wrapped too: if it raises before the del below ever runs, api_key
        # would otherwise still be bound in this frame's locals.
        try:
            key_hash = self._hash_api_key(api_key)
        except BaseException:
            # api_key is declared str, not str | None, so it is scrubbed to
            # "" here rather than reassigned to None (which `del` below
            # would otherwise handle) -- and not `del`-ed either, since a
            # `del` on this branch alone would make ruff's flow analysis
            # treat the unconditional `del api_key` below as a possible
            # double-delete.
            api_key = ""
            raise
        del api_key

        # Look up the key in the backend
        try:
            key_info = await self.backend.get(key_hash)
        except BaseException:
            # Mirrors the scrub-on-BaseException pattern already used in
            # __call__ and controllers.create_api_key: an unexpected backend
            # error (bug/outage) is about to propagate out of this frame
            # while it still holds key_hash -- scrub it too before it
            # propagates.
            key_hash = None
            raise

        if key_info is None:
            raise APIKeyNotFoundError()

        try:
            self._check_key_info_is_valid(key_info)
        except BaseException:
            # Mirrors the scrub-on-BaseException pattern above for
            # backend.get(): an unexpected error here (e.g. a corrupted
            # expires_at making key_info.is_expired raise) must not leave
            # key_hash/key_info bound in this frame while it propagates.
            # api_key itself was already dropped above, but key_hash and
            # key_info are still sensitive verifier state per this class's
            # own redaction convention (see the key_hash="" redaction in
            # __call__'s else clause).
            key_hash = key_info = None
            raise

        return key_info

    def _check_key_info_is_valid(self, key_info: APIKeyInfo) -> None:
        """Validate an already-fetched ``APIKeyInfo`` record.

        Shared by ``_validate_api_key`` (against the initial ``backend.get()``
        snapshot) and ``__call__`` (against a fresher record a backend's
        ``update_last_used()`` may return -- see the "Revocation timing"
        section of this class's docstring), so both call sites reject a
        revoked, expired, or malformed record the same way.

        Args:
            key_info: The record to validate.

        Raises:
            InvalidAPIKeyError: If the record's field types cannot be trusted.
            APIKeyRevokedError: If the key has been revoked.
            APIKeyExpiredError: If the key has expired.
        """
        # A backend record whose is_active/scopes fields don't actually match
        # the types APIKeyInfo declares must not be trusted: msgspec.Struct
        # does not enforce field types on direct construction, so a
        # custom/legacy backend, migrated or corrupted data, or direct
        # programmatic seeding could otherwise fail open here -- e.g. a
        # truthy non-bool is_active (the string "false") would pass the
        # check below, and a scopes value that is a str instead of a
        # list[str] would turn has_scope's membership check into a substring
        # match. See APIKeyInfo.has_valid_types.
        if not key_info.has_valid_types:
            raise InvalidAPIKeyError(reason="backend record has invalid field types")

        # Check if the key is revoked
        if not key_info.is_active:
            raise APIKeyRevokedError(key_id=key_info.key_id)

        # Check if the key is expired
        if key_info.is_expired:
            raise APIKeyExpiredError(
                key_id=key_info.key_id,
                expired_at=key_info.expires_at,
            )

    def _hash_api_key(self, api_key: str) -> str:
        """Hash an API key for backend lookup.

        Delegates to :func:`litestar_api_auth.service.hash_api_key` so the
        middleware always hashes with the same algorithm the key generation
        service uses, even if that algorithm changes later.

        Args:
            api_key: The raw API key value.

        Returns:
            The hashed API key.
        """
        return hash_api_key(api_key)
