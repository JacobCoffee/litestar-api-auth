"""Unit tests for APIKeyMiddleware.

These tests exercise APIKeyMiddleware.__call__ directly against a raw ASGI
scope, without going through a full Litestar app, so that scope["state"]
can be inspected precisely.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import TracebackType
from typing import Any

import pytest

from litestar_api_auth.backends.base import APIKeyInfo
from litestar_api_auth.backends.memory import MemoryBackend
from litestar_api_auth.exceptions import (
    APIKeyExpiredError,
    APIKeyNotFoundError,
    APIKeyRevokedError,
    InvalidAPIKeyError,
)
from litestar_api_auth.middleware import APIKeyMiddleware
from litestar_api_auth.service import generate_api_key


async def _dummy_app(_scope: dict[str, Any], _receive: Any, _send: Any) -> None:
    """Minimal downstream ASGI app that does nothing."""
    return


async def _exploding_app(_scope: dict[str, Any], _receive: Any, _send: Any) -> None:
    """Downstream ASGI app that always raises, to exercise the middleware's
    frame locals at the point an unhandled downstream error propagates."""
    raise RuntimeError("downstream failure")


def _find_middleware_frame_locals(tb: TracebackType | None) -> dict[str, Any] | None:
    """Walk a traceback and return the locals of the ``APIKeyMiddleware.__call__``
    frame, or None if no such frame is found.

    Matches on both the code object's name *and* ``self`` being the
    middleware instance -- Litestar wraps middleware instances in its own
    ``wrapped_call`` closures that also bind a ``self`` referencing this
    middleware but are a different frame with no ``api_key`` local at all,
    which would make a name-only or self-only match pass vacuously.
    """
    while tb is not None:
        frame = tb.tb_frame
        if frame.f_code.co_name == "__call__" and isinstance(frame.f_locals.get("self"), APIKeyMiddleware):
            return frame.f_locals
        tb = tb.tb_next
    return None


def _find_validate_api_key_frame_locals(tb: TracebackType | None) -> dict[str, Any] | None:
    """Walk a traceback and return the locals of the
    ``APIKeyMiddleware._validate_api_key`` frame, or None if no such frame is
    found.

    Matches on both the code object's name *and* ``self`` being the
    middleware instance, for the same reason ``_find_middleware_frame_locals``
    does.
    """
    while tb is not None:
        frame = tb.tb_frame
        if frame.f_code.co_name == "_validate_api_key" and isinstance(frame.f_locals.get("self"), APIKeyMiddleware):
            return frame.f_locals
        tb = tb.tb_next
    return None


async def _noop_receive() -> dict[str, Any]:
    return {"type": "http.request", "body": b"", "more_body": False}


async def _noop_send(_message: dict[str, Any]) -> None:
    return None


def _make_scope(headers: list[tuple[bytes, bytes]], stale_api_key: object, scope_type: str = "http") -> dict[str, Any]:
    """Build a raw ASGI scope with a pre-existing (stale) state["api_key"].

    Simulates an upstream middleware (or a reused/pooled scope) that already
    populated ``state["api_key"]`` before ``APIKeyMiddleware`` ran.
    """
    return {
        "type": scope_type,
        "headers": headers,
        "state": {"api_key": stale_api_key},
    }


class TestStaleStateIsCleared:
    """Regression tests: the middleware must never leave a pre-existing
    ``scope["state"]["api_key"]`` in place when it does not itself validate
    a key on the current request.

    Before the fix, the ``if api_key:`` block was skipped entirely when no
    header was present, and the ``except`` block on validation failure just
    ``pass``-ed, so in both cases a stale/upstream-set ``state["api_key"]``
    survived and would be trusted by guards (see ``guards.get_api_key_info``).
    """

    async def test_no_header_clears_stale_state(self) -> None:
        """No API key header at all must clear a pre-existing state["api_key"]."""
        backend = MemoryBackend()
        middleware = APIKeyMiddleware(app=_dummy_app, backend=backend)  # type: ignore[arg-type]

        stale = APIKeyInfo(key_id="stale", key_hash="stale-hash", name="Stale", scopes=["admin:all"])
        scope = _make_scope(headers=[], stale_api_key=stale)

        await middleware(scope, _noop_receive, _noop_send)  # type: ignore[arg-type]

        assert scope["state"]["api_key"] is None

    async def test_invalid_header_clears_stale_state(self) -> None:
        """An API key that fails validation (not found) must clear stale state."""
        backend = MemoryBackend()
        middleware = APIKeyMiddleware(app=_dummy_app, backend=backend)  # type: ignore[arg-type]

        stale = APIKeyInfo(key_id="stale", key_hash="stale-hash", name="Stale", scopes=["admin:all"])
        scope = _make_scope(
            headers=[(b"x-api-key", b"does-not-exist")],
            stale_api_key=stale,
        )

        await middleware(scope, _noop_receive, _noop_send)  # type: ignore[arg-type]

        assert scope["state"]["api_key"] is None

    async def test_revoked_key_clears_stale_state(self) -> None:
        """A revoked key must clear stale state rather than leaving it in place."""
        backend = MemoryBackend()
        raw_key, key_hash = generate_api_key(prefix="test_")
        await backend.create(
            key_hash,
            APIKeyInfo(key_id="revoked", key_hash=key_hash, name="Revoked", scopes=["read:users"], is_active=False),
        )
        middleware = APIKeyMiddleware(app=_dummy_app, backend=backend)  # type: ignore[arg-type]

        stale = APIKeyInfo(key_id="stale", key_hash="stale-hash", name="Stale", scopes=["admin:all"])
        scope = _make_scope(
            headers=[(b"x-api-key", raw_key.encode())],
            stale_api_key=stale,
        )

        await middleware(scope, _noop_receive, _noop_send)  # type: ignore[arg-type]

        assert scope["state"]["api_key"] is None

    async def test_expired_key_clears_stale_state(self) -> None:
        """An expired key must clear stale state rather than leaving it in place."""
        backend = MemoryBackend()
        raw_key, key_hash = generate_api_key(prefix="test_")
        await backend.create(
            key_hash,
            APIKeyInfo(
                key_id="expired",
                key_hash=key_hash,
                name="Expired",
                scopes=["read:users"],
                expires_at=datetime.now(timezone.utc) - timedelta(days=1),
            ),
        )
        middleware = APIKeyMiddleware(app=_dummy_app, backend=backend)  # type: ignore[arg-type]

        stale = APIKeyInfo(key_id="stale", key_hash="stale-hash", name="Stale", scopes=["admin:all"])
        scope = _make_scope(
            headers=[(b"x-api-key", raw_key.encode())],
            stale_api_key=stale,
        )

        await middleware(scope, _noop_receive, _noop_send)  # type: ignore[arg-type]

        assert scope["state"]["api_key"] is None

    async def test_websocket_scope_clears_stale_state(self) -> None:
        """A WebSocket scope must also have stale state cleared.

        ``AbstractMiddleware`` routes both HTTP and WebSocket scopes to this
        middleware by default (``scopes = {ScopeType.HTTP, ScopeType.WEBSOCKET}``),
        but this middleware only *authenticates* HTTP requests. Before the
        fix, the HTTP-only early return happened before state was cleared,
        so a stale ``state["api_key"]`` would still reach WebSocket guards.
        """
        backend = MemoryBackend()
        middleware = APIKeyMiddleware(app=_dummy_app, backend=backend)  # type: ignore[arg-type]

        stale = APIKeyInfo(key_id="stale", key_hash="stale-hash", name="Stale", scopes=["admin:all"])
        scope = _make_scope(headers=[], stale_api_key=stale, scope_type="websocket")

        await middleware(scope, _noop_receive, _noop_send)  # type: ignore[arg-type]

        assert scope["state"]["api_key"] is None

    async def test_valid_key_still_sets_correct_state(self) -> None:
        """Sanity check: a valid key must still populate state with its own info."""
        backend = MemoryBackend()
        raw_key, key_hash = generate_api_key(prefix="test_")
        await backend.create(
            key_hash,
            APIKeyInfo(key_id="good", key_hash=key_hash, name="Good", scopes=["read:users"]),
        )
        middleware = APIKeyMiddleware(app=_dummy_app, backend=backend)  # type: ignore[arg-type]

        stale = APIKeyInfo(key_id="stale", key_hash="stale-hash", name="Stale", scopes=["admin:all"])
        scope = _make_scope(
            headers=[(b"x-api-key", raw_key.encode())],
            stale_api_key=stale,
        )

        await middleware(scope, _noop_receive, _noop_send)  # type: ignore[arg-type]

        assert scope["state"]["api_key"] is not None
        assert scope["state"]["api_key"].key_id == "good"


class TestMalformedBackendRecordFailsClosed:
    """Regression tests: a backend record whose ``is_active``/``scopes``
    fields don't match the types ``APIKeyInfo`` declares must not be trusted.

    ``msgspec.Struct`` does not type-check on direct construction, so a
    custom/legacy backend, migrated or corrupted serialized data, or direct
    programmatic seeding can hand ``_validate_api_key`` an ``APIKeyInfo``
    whose ``is_active`` is a truthy non-``bool`` (e.g. the string "false")
    or whose ``scopes`` is a ``str`` instead of a ``list[str]``. Before the
    fix, ``not "false"`` is ``False``, so such a record sailed past the
    revocation check here and was stored in ``state["api_key"]`` -- and
    ``"admin" in "api_keys:admin"`` is a substring match, so a downstream
    ``require_scope("admin")`` guard would then have granted access the
    record never actually held as a scope list member.
    """

    async def test_string_is_active_fails_closed(self) -> None:
        """A record with ``is_active="false"`` must not populate state["api_key"]."""
        backend = MemoryBackend()
        raw_key, key_hash = generate_api_key(prefix="test_")
        await backend.create(
            key_hash,
            APIKeyInfo(
                key_id="malformed",
                key_hash=key_hash,
                name="Malformed",
                scopes=["api_keys:admin"],
                is_active="false",  # type: ignore[arg-type]
            ),
        )
        middleware = APIKeyMiddleware(app=_dummy_app, backend=backend)  # type: ignore[arg-type]

        scope = _make_scope(headers=[(b"x-api-key", raw_key.encode())], stale_api_key=None)

        await middleware(scope, _noop_receive, _noop_send)  # type: ignore[arg-type]

        assert scope["state"]["api_key"] is None

    async def test_string_scopes_fails_closed(self) -> None:
        """A record with ``scopes`` as a ``str`` must not populate state["api_key"]."""
        backend = MemoryBackend()
        raw_key, key_hash = generate_api_key(prefix="test_")
        await backend.create(
            key_hash,
            APIKeyInfo(
                key_id="malformed",
                key_hash=key_hash,
                name="Malformed",
                scopes="api_keys:admin",  # type: ignore[arg-type]
            ),
        )
        middleware = APIKeyMiddleware(app=_dummy_app, backend=backend)  # type: ignore[arg-type]

        scope = _make_scope(headers=[(b"x-api-key", raw_key.encode())], stale_api_key=None)

        await middleware(scope, _noop_receive, _noop_send)  # type: ignore[arg-type]

        assert scope["state"]["api_key"] is None


class _RevokedDuringUpdateBackend(MemoryBackend):
    """A race-aware backend that detects concurrent revocation inside update_last_used().

    Simulates a backend where get() still reports an active key (as checked
    moments earlier by _validate_api_key), but a concurrent revocation is
    detected only when the usage-tracking write actually runs.
    """

    async def update_last_used(self, key_hash: str) -> None:
        raise APIKeyRevokedError(key_id="raced-out")


class _ExpiredDuringUpdateBackend(MemoryBackend):
    """A race-aware backend that detects concurrent expiry inside update_last_used()."""

    async def update_last_used(self, key_hash: str) -> None:
        raise APIKeyExpiredError(key_id="raced-out")


class _NotFoundDuringUpdateBackend(MemoryBackend):
    """A race-aware backend that detects concurrent deletion inside update_last_used()."""

    async def update_last_used(self, key_hash: str) -> None:
        raise APIKeyNotFoundError(key_id="raced-out")


class _InvalidDuringUpdateBackend(MemoryBackend):
    """A backend whose update_last_used() rejects the key as invalid.

    Exercises the fourth member of the validation-exception tuple so all of
    it, not just the revocation/expiry cases, is proven to clear state.
    """

    async def update_last_used(self, key_hash: str) -> None:
        raise InvalidAPIKeyError(reason="raced-out")


class TestUpdateLastUsedRevocationRaceIsNotSwallowed:
    """Regression tests for the revocation-race finding.

    Before the fix, ``update_last_used()`` ran inside the same try block that
    caught ``APIKeyNotFoundError``/``APIKeyExpiredError``/``APIKeyRevokedError``/
    ``InvalidAPIKeyError`` from validation, but only *after*
    ``state["api_key"]`` had already been populated. A race-aware custom
    backend raising any of those exceptions from ``update_last_used()`` (e.g.
    after detecting a concurrent revocation or deletion) was silently
    swallowed, and the just-invalidated key's request reached guarded
    handlers still authenticated.
    """

    async def test_revocation_detected_during_update_clears_state(self) -> None:
        """APIKeyRevokedError from update_last_used() must clear state["api_key"]."""
        backend = _RevokedDuringUpdateBackend()
        raw_key, key_hash = generate_api_key(prefix="test_")
        await backend.create(
            key_hash,
            APIKeyInfo(key_id="good", key_hash=key_hash, name="Good", scopes=["read:users"]),
        )
        middleware = APIKeyMiddleware(app=_dummy_app, backend=backend)  # type: ignore[arg-type]

        scope = _make_scope(headers=[(b"x-api-key", raw_key.encode())], stale_api_key=None)

        # Must not raise -- and must not leave the request authenticated.
        await middleware(scope, _noop_receive, _noop_send)  # type: ignore[arg-type]

        assert scope["state"]["api_key"] is None

    async def test_expiry_detected_during_update_clears_state(self) -> None:
        """APIKeyExpiredError from update_last_used() must clear state["api_key"]."""
        backend = _ExpiredDuringUpdateBackend()
        raw_key, key_hash = generate_api_key(prefix="test_")
        await backend.create(
            key_hash,
            APIKeyInfo(key_id="good", key_hash=key_hash, name="Good", scopes=["read:users"]),
        )
        middleware = APIKeyMiddleware(app=_dummy_app, backend=backend)  # type: ignore[arg-type]

        scope = _make_scope(headers=[(b"x-api-key", raw_key.encode())], stale_api_key=None)

        await middleware(scope, _noop_receive, _noop_send)  # type: ignore[arg-type]

        assert scope["state"]["api_key"] is None

    async def test_not_found_detected_during_update_clears_state(self) -> None:
        """APIKeyNotFoundError from update_last_used() must clear state["api_key"]."""
        backend = _NotFoundDuringUpdateBackend()
        raw_key, key_hash = generate_api_key(prefix="test_")
        await backend.create(
            key_hash,
            APIKeyInfo(key_id="good", key_hash=key_hash, name="Good", scopes=["read:users"]),
        )
        middleware = APIKeyMiddleware(app=_dummy_app, backend=backend)  # type: ignore[arg-type]

        scope = _make_scope(headers=[(b"x-api-key", raw_key.encode())], stale_api_key=None)

        await middleware(scope, _noop_receive, _noop_send)  # type: ignore[arg-type]

        assert scope["state"]["api_key"] is None

    async def test_invalid_key_detected_during_update_clears_state(self) -> None:
        """InvalidAPIKeyError from update_last_used() must clear state["api_key"]."""
        backend = _InvalidDuringUpdateBackend()
        raw_key, key_hash = generate_api_key(prefix="test_")
        await backend.create(
            key_hash,
            APIKeyInfo(key_id="good", key_hash=key_hash, name="Good", scopes=["read:users"]),
        )
        middleware = APIKeyMiddleware(app=_dummy_app, backend=backend)  # type: ignore[arg-type]

        scope = _make_scope(headers=[(b"x-api-key", raw_key.encode())], stale_api_key=None)

        await middleware(scope, _noop_receive, _noop_send)  # type: ignore[arg-type]

        assert scope["state"]["api_key"] is None


class TestApiKeyHashIsRedactedFromState:
    """Regression test: ``request.state.api_key`` must never carry the real
    ``key_hash``.

    ``guards.get_api_key_info``'s docstring warns against returning or
    serializing its result directly -- precisely because, before this fix,
    the middleware stored the exact ``backends.base.APIKeyInfo`` instance
    returned by the backend -- including its real SHA-256 ``key_hash`` --
    in ``scope["state"]["api_key"]``. A handler ignoring that warning
    would leak the hash used for backend lookups into the HTTP response.
    """

    async def test_valid_key_state_has_redacted_hash(self) -> None:
        """A validated key's hash must be blanked out before it reaches state."""
        backend = MemoryBackend()
        raw_key, key_hash = generate_api_key(prefix="test_")
        await backend.create(
            key_hash,
            APIKeyInfo(key_id="good", key_hash=key_hash, name="Good", scopes=["read:users"]),
        )
        middleware = APIKeyMiddleware(app=_dummy_app, backend=backend)  # type: ignore[arg-type]

        scope = _make_scope(headers=[(b"x-api-key", raw_key.encode())], stale_api_key=None)

        await middleware(scope, _noop_receive, _noop_send)  # type: ignore[arg-type]

        stored = scope["state"]["api_key"]
        assert stored is not None
        assert stored.key_id == "good"
        # The real hash must never reach request state, since guards'
        # documented usage returns/serializes this object directly.
        assert stored.key_hash == ""
        assert stored.key_hash != key_hash


class _UsageTrackingFailsBackend(MemoryBackend):
    """A backend whose usage tracking always fails.

    Mirrors the RedisBackend contract: ``update_last_used()`` can raise
    ``RuntimeError`` (e.g. after exhausting its WATCH/MULTI retries under
    write contention), while ``get()`` keeps working normally.
    """

    async def update_last_used(self, key_hash: str) -> None:
        msg = "Failed to update API key due to concurrent writes"
        raise RuntimeError(msg)


class TestUpdateLastUsedIsBestEffort:
    """Regression tests: a failing usage-tracking write must not fail authentication.

    Before the fix, ``await self.backend.update_last_used(key_hash)`` was
    unguarded inside the same try block as key validation. A backend that
    raises RuntimeError there (as RedisBackend now can, once its update()
    retries are exhausted -- see the delete/revoke resurrection fix) would
    propagate out of the middleware and turn an otherwise valid,
    already-authenticated request into an unhandled exception.
    """

    async def test_update_last_used_failure_does_not_fail_the_request(self) -> None:
        """A RuntimeError from update_last_used() must not raise or clear valid state."""
        backend = _UsageTrackingFailsBackend()
        raw_key, key_hash = generate_api_key(prefix="test_")
        await backend.create(
            key_hash,
            APIKeyInfo(key_id="good", key_hash=key_hash, name="Good", scopes=["read:users"]),
        )
        middleware = APIKeyMiddleware(app=_dummy_app, backend=backend)  # type: ignore[arg-type]

        scope = _make_scope(headers=[(b"x-api-key", raw_key.encode())], stale_api_key=None)

        # Must not raise, despite update_last_used() always failing.
        await middleware(scope, _noop_receive, _noop_send)  # type: ignore[arg-type]

        assert scope["state"]["api_key"] is not None
        assert scope["state"]["api_key"].key_id == "good"


class TestRawApiKeyScrubbedFromLocalsBeforeDownstreamApp:
    """Regression test: the raw ``X-API-Key`` header value must not remain
    directly bound in ``APIKeyMiddleware.__call__``'s locals (as its own
    ``api_key``/``key_hash``/``key_info`` names) while the downstream app is
    awaited.

    Before the fix, ``api_key`` (the raw bearer key straight off the request
    header), and ``key_hash``/``key_info`` derived from it, stayed bound in
    this frame for the entire ``await self.app(scope, receive, send)`` call,
    even though none of them are read again after validation. If the
    downstream app raised, a monitoring tool capturing frame locals on
    unhandled exceptions (e.g. Sentry with ``include_local_variables=True``)
    could recover them straight out of the traceback. After the fix, these
    locals are cleared before the downstream app is invoked.

    Note this only removes the library's own redundant direct references.
    It cannot -- and does not attempt to -- redact ``scope["headers"]``
    itself: ASGI requires the original headers to remain available to
    downstream middleware/handlers, so the raw key is still reachable via
    ``scope`` from the downstream app's own frame. Closing that would mean
    stripping the auth header from every downstream request, which is a
    breaking behavior change outside the scope of this fix.
    """

    async def test_raw_key_not_in_locals_when_downstream_raises(self) -> None:
        backend = MemoryBackend()
        raw_key, key_hash = generate_api_key(prefix="test_")
        await backend.create(
            key_hash,
            APIKeyInfo(key_id="good", key_hash=key_hash, name="Good", scopes=["read:users"]),
        )
        middleware = APIKeyMiddleware(app=_exploding_app, backend=backend)  # type: ignore[arg-type]

        scope = _make_scope(headers=[(b"x-api-key", raw_key.encode())], stale_api_key=None)

        with pytest.raises(RuntimeError, match="downstream failure") as exc_info:
            await middleware(scope, _noop_receive, _noop_send)  # type: ignore[arg-type]

        frame_locals = _find_middleware_frame_locals(exc_info.value.__traceback__)

        assert frame_locals is not None, "traceback did not include APIKeyMiddleware.__call__'s frame"
        assert frame_locals.get("api_key") is None
        assert frame_locals.get("key_hash") is None
        assert frame_locals.get("key_info") is None


class _UnexpectedErrorOnGetBackend(MemoryBackend):
    """A backend whose ``get()`` raises an error outside the four expected
    validation-failure types (not found/expired/revoked/invalid).

    Mirrors a real backend bug or outage (e.g. a dropped connection) during
    key lookup, which ``APIKeyMiddleware.__call__`` does not (and should
    not) swallow -- unlike ``APIKeyNotFoundError`` et al., this must still
    propagate as an unhandled error.
    """

    async def get(self, key_hash: str) -> APIKeyInfo | None:
        msg = "backend connection dropped"
        raise ConnectionError(msg)


class TestRawApiKeyScrubbedFromLocalsOnUnexpectedValidationError:
    """Regression test: an *unexpected* error during key validation (not one
    of the four expected validation-failure exceptions) must not leave the
    raw ``api_key`` reachable from ``APIKeyMiddleware.__call__``'s locals
    while it propagates.

    Before the fix, only the four expected validation-failure exceptions
    were caught; any other exception raised by ``backend.get()`` (called
    from ``_validate_api_key``, awaited at line ~150) propagated straight
    out of ``__call__`` without ever reaching the scrub that runs just
    before the downstream app is awaited -- so this frame's ``api_key``
    local was still the raw key when a monitoring tool captured it.
    """

    async def test_raw_key_not_in_locals_when_validation_raises_unexpectedly(self) -> None:
        backend = _UnexpectedErrorOnGetBackend()
        raw_key, key_hash = generate_api_key(prefix="test_")
        await backend.create(
            key_hash,
            APIKeyInfo(key_id="good", key_hash=key_hash, name="Good", scopes=["read:users"]),
        )
        middleware = APIKeyMiddleware(app=_dummy_app, backend=backend)  # type: ignore[arg-type]

        scope = _make_scope(headers=[(b"x-api-key", raw_key.encode())], stale_api_key=None)

        with pytest.raises(ConnectionError, match="backend connection dropped") as exc_info:
            await middleware(scope, _noop_receive, _noop_send)  # type: ignore[arg-type]

        frame_locals = _find_middleware_frame_locals(exc_info.value.__traceback__)

        assert frame_locals is not None, "traceback did not include APIKeyMiddleware.__call__'s frame"
        assert frame_locals.get("api_key") is None


class TestRawApiKeyScrubbedFromValidateApiKeyLocalsOnUnexpectedBackendError:
    """Regression test: an *unexpected* error raised by the backend while
    ``_validate_api_key`` is on the stack must not leave the raw API key
    reachable from ``_validate_api_key``'s own locals while it propagates.

    Before the fix, ``__call__``'s ``BaseException`` handler only scrubbed
    ``api_key``/``key_hash``/``key_info`` from its *own* frame. The inner
    ``_validate_api_key`` frame -- still present in the traceback because it
    is the one that actually awaited ``backend.get()`` -- kept the raw
    ``api_key`` (and ``key_hash``) bound as its own locals, so a monitoring
    tool capturing frame locals on the propagating exception (e.g. Sentry's
    ``include_local_variables``) could recover the plaintext bearer key from
    that inner frame even though the outer frame was clean.
    """

    async def test_raw_key_not_in_validate_api_key_locals_when_backend_raises_unexpectedly(self) -> None:
        backend = _UnexpectedErrorOnGetBackend()
        raw_key, key_hash = generate_api_key(prefix="test_")
        await backend.create(
            key_hash,
            APIKeyInfo(key_id="good", key_hash=key_hash, name="Good", scopes=["read:users"]),
        )
        middleware = APIKeyMiddleware(app=_dummy_app, backend=backend)  # type: ignore[arg-type]

        scope = _make_scope(headers=[(b"x-api-key", raw_key.encode())], stale_api_key=None)

        with pytest.raises(ConnectionError, match="backend connection dropped") as exc_info:
            await middleware(scope, _noop_receive, _noop_send)  # type: ignore[arg-type]

        frame_locals = _find_validate_api_key_frame_locals(exc_info.value.__traceback__)

        assert frame_locals is not None, "traceback did not include APIKeyMiddleware._validate_api_key's frame"
        assert frame_locals.get("api_key") is None
        assert frame_locals.get("key_hash") is None
        assert frame_locals.get("key_info") is None


class _KeyInfoWithExplodingIsExpired:
    """Stand-in for ``APIKeyInfo`` whose ``is_expired`` property raises
    unexpectedly, simulating a bug in a backend's expiry-tracking data (e.g.
    a corrupted or non-UTC ``expires_at`` value that a real backend's own
    ``is_expired``-equivalent logic chokes on).

    Deliberately duck-typed rather than a real ``APIKeyInfo`` instance, since
    only the attributes ``_validate_api_key`` actually reads (``has_valid_types``,
    ``is_active``, ``is_expired``, ``key_id``) need to be present.
    """

    has_valid_types = True
    is_active = True
    key_id = "good"

    @property
    def is_expired(self) -> bool:
        msg = "corrupted expiry data"
        raise RuntimeError(msg)


class _ExplodingIsExpiredBackend(MemoryBackend):
    """A backend whose ``get()`` succeeds but returns a ``key_info`` whose
    ``is_expired`` property raises, so the unexpected error happens *after*
    the backend lookup, inside ``_validate_api_key``'s own validation checks.
    """

    async def get(self, key_hash: str) -> APIKeyInfo | None:
        return _KeyInfoWithExplodingIsExpired()  # type: ignore[return-value]


class TestRawApiKeyScrubbedFromValidateApiKeyLocalsOnUnexpectedPostLookupError:
    """Regression test: an *unexpected* error raised by ``key_info.is_expired``
    (i.e. after a successful backend lookup, not from ``backend.get()``
    itself) must still not leave the raw API key reachable from
    ``_validate_api_key``'s locals while it propagates.

    A fix that only wrapped the ``backend.get()`` call in a scrub-on-except
    handler (rather than deleting ``api_key`` as soon as it is hashed, before
    the lookup) would still leave ``api_key`` bound in this frame for this
    scenario, since the exception occurs after that ``try``/``except`` block
    has already exited successfully.
    """

    async def test_raw_key_not_in_validate_api_key_locals_when_is_expired_raises_unexpectedly(self) -> None:
        backend = _ExplodingIsExpiredBackend()
        raw_key, key_hash = generate_api_key(prefix="test_")
        await backend.create(
            key_hash,
            APIKeyInfo(key_id="good", key_hash=key_hash, name="Good", scopes=["read:users"]),
        )
        middleware = APIKeyMiddleware(app=_dummy_app, backend=backend)  # type: ignore[arg-type]

        scope = _make_scope(headers=[(b"x-api-key", raw_key.encode())], stale_api_key=None)

        with pytest.raises(RuntimeError, match="corrupted expiry data") as exc_info:
            await middleware(scope, _noop_receive, _noop_send)  # type: ignore[arg-type]

        frame_locals = _find_validate_api_key_frame_locals(exc_info.value.__traceback__)

        assert frame_locals is not None, "traceback did not include APIKeyMiddleware._validate_api_key's frame"
        assert frame_locals.get("api_key") is None
