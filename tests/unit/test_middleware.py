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


class TestRealBackendClosesUpdateLastUsedRevocationRace:
    """Regression tests for the revocation-handoff race finding (Codex).

    Unlike ``TestUpdateLastUsedRevocationRaceIsNotSwallowed`` above (which
    proves the middleware *reacts correctly* to a hand-rolled race-aware
    backend), these tests exercise the real, shipped ``MemoryBackend`` and
    reproduce the exact interleaving from the finding: ``backend.get()``
    returns an active snapshot, then a concurrent ``revoke()`` commits
    before ``update_last_used()`` runs moments later in the same request.

    Before the fix, ``MemoryBackend.update_last_used()`` (like the Redis and
    SQLAlchemy backends) discarded its own return value entirely, so the
    middleware kept trusting the stale, pre-revocation ``key_info`` snapshot
    and authenticated the request anyway. After the fix, ``update_last_used()``
    returns the freshly written record, which the middleware re-validates --
    closing the race for a concurrent revoke(), though a concurrent delete()
    in the same window is still not caught (see the "Revocation timing"
    section of ``APIKeyMiddleware``'s docstring for why).
    """

    async def test_concurrent_revoke_between_get_and_update_last_used_is_caught(self) -> None:
        """A revoke() landing right after backend.get() but before
        update_last_used() must not leave the request authenticated.
        """
        backend = MemoryBackend()
        raw_key, key_hash = generate_api_key(prefix="test_")
        await backend.create(
            key_hash,
            APIKeyInfo(key_id="raced-revoke", key_hash=key_hash, name="Raced", scopes=["read:users"]),
        )
        middleware = APIKeyMiddleware(app=_dummy_app, backend=backend)  # type: ignore[arg-type]

        # Simulate a concurrent request's revoke() landing in the exact
        # window the finding describes: right after this request's
        # backend.get() call has captured its (still-active) snapshot, but
        # before update_last_used() runs a few lines later in __call__.
        original_get = backend.get

        async def get_then_race_revoke(key_hash_arg: str) -> APIKeyInfo | None:
            info = await original_get(key_hash_arg)
            await backend.revoke(key_hash_arg)
            return info

        backend.get = get_then_race_revoke  # type: ignore[method-assign]

        scope = _make_scope(headers=[(b"x-api-key", raw_key.encode())], stale_api_key=None)

        await middleware(scope, _noop_receive, _noop_send)  # type: ignore[arg-type]

        # Before the fix this was the stale, pre-revocation active snapshot.
        assert scope["state"]["api_key"] is None

    async def test_concurrent_expiry_shortening_between_get_and_update_last_used_is_caught(self) -> None:
        """An update() that shortens expires_at in the same window must
        also be caught, not just a revoke().
        """
        backend = MemoryBackend()
        raw_key, key_hash = generate_api_key(prefix="test_")
        await backend.create(
            key_hash,
            APIKeyInfo(
                key_id="raced-expiry",
                key_hash=key_hash,
                name="Raced Expiry",
                scopes=["read:users"],
                expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            ),
        )
        middleware = APIKeyMiddleware(app=_dummy_app, backend=backend)  # type: ignore[arg-type]

        original_get = backend.get

        async def get_then_race_shorten_expiry(key_hash_arg: str) -> APIKeyInfo | None:
            info = await original_get(key_hash_arg)
            await backend.update(key_hash_arg, expires_at=datetime.now(timezone.utc) - timedelta(seconds=1))
            return info

        backend.get = get_then_race_shorten_expiry  # type: ignore[method-assign]

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


class _ExplodingHashMiddleware(APIKeyMiddleware):
    """Middleware whose ``_hash_api_key`` raises unexpectedly, simulating a
    bug in the hashing step itself (as opposed to the backend lookup or the
    post-lookup validity checks already covered above).
    """

    def _hash_api_key(self, api_key: str) -> str:
        msg = "hash failed"
        raise RuntimeError(msg)


class TestRawApiKeyScrubbedFromValidateApiKeyLocalsOnUnexpectedHashError:
    """Regression test: an *unexpected* error raised by ``_hash_api_key``
    itself -- before the raw key has even been hashed and dropped -- must
    not leave it reachable from ``_validate_api_key``'s locals while it
    propagates.

    Before the fix, ``key_hash = self._hash_api_key(api_key)`` was not
    guarded: if ``_hash_api_key`` raised, execution never reached the
    ``del api_key`` on the following line, so ``api_key`` stayed bound as
    this frame's local for the rest of the exception's life.
    """

    async def test_raw_key_not_in_validate_api_key_locals_when_hash_raises_unexpectedly(self) -> None:
        backend = MemoryBackend()
        middleware = _ExplodingHashMiddleware(app=_dummy_app, backend=backend)  # type: ignore[arg-type]

        raw_key, _key_hash = generate_api_key(prefix="test_")
        scope = _make_scope(headers=[(b"x-api-key", raw_key.encode())], stale_api_key=None)

        with pytest.raises(RuntimeError, match="hash failed") as exc_info:
            await middleware(scope, _noop_receive, _noop_send)  # type: ignore[arg-type]

        frame_locals = _find_validate_api_key_frame_locals(exc_info.value.__traceback__)

        assert frame_locals is not None, "traceback did not include APIKeyMiddleware._validate_api_key's frame"
        # api_key is declared `str` (not `str | None`), so the scrub here is
        # "" rather than None -- either way, the raw key itself is gone.
        assert frame_locals.get("api_key") == ""


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
    has already exited successfully. ``key_hash``/``key_info`` are checked
    too: they are the SHA-256 verifier and the (still-unredacted) backend
    record, both treated as sensitive elsewhere in this class.
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
        assert frame_locals.get("key_hash") is None
        assert frame_locals.get("key_info") is None


class _NonStructKeyInfo:
    """Stand-in for ``APIKeyInfo`` that duck-types its way past
    ``_check_key_info_is_valid`` (matching ``has_valid_types``/``is_active``/
    ``is_expired``/``key_id``) but is not an actual ``msgspec.Struct``, so
    ``msgspec.structs.replace()`` raises ``TypeError`` against it.

    Simulates a custom ``APIKeyBackend`` implementation returning its own
    record type that satisfies the ``APIKeyBackend``/validation duck-typing
    contract without being built from ``msgspec.Struct``.
    """

    has_valid_types = True
    is_active = True
    is_expired = False
    key_id = "good"


class _NonStructBackend(MemoryBackend):
    """A backend whose ``get()`` succeeds and returns a valid-looking but
    non-``msgspec.Struct`` ``key_info``, so ``__call__``'s ``else`` clause
    (not the ``try`` it is attached to) is what raises.
    """

    async def get(self, key_hash: str) -> APIKeyInfo | None:
        return _NonStructKeyInfo()  # type: ignore[return-value]


class TestRawApiKeyScrubbedFromLocalsOnUnexpectedElseClauseError:
    """Regression test: an *unexpected* error raised while building the
    redacted ``state["api_key"]`` value -- in the ``else`` clause of
    ``__call__``'s ``try``/``except``/``else`` -- must not leave the raw
    ``api_key`` reachable from ``__call__``'s locals while it propagates.

    Exceptions raised in an ``else`` clause are *not* caught by the
    ``except`` clauses attached to that same ``try`` statement (this is
    plain Python control-flow, not a bug specific to this class), so the
    existing ``except BaseException: ... scrub ...; raise`` above the
    ``else`` clause does not run for this case. Before the fix, this left
    ``api_key`` bound in ``__call__``'s frame for a ``TypeError`` raised by
    ``msgspec.structs.replace()`` against a non-``msgspec.Struct`` ``key_info``.
    """

    async def test_raw_key_not_in_locals_when_else_clause_raises_unexpectedly(self) -> None:
        backend = _NonStructBackend()
        raw_key, key_hash = generate_api_key(prefix="test_")
        await backend.create(
            key_hash,
            APIKeyInfo(key_id="good", key_hash=key_hash, name="Good", scopes=["read:users"]),
        )
        middleware = APIKeyMiddleware(app=_dummy_app, backend=backend, update_last_used=False)  # type: ignore[arg-type]

        scope = _make_scope(headers=[(b"x-api-key", raw_key.encode())], stale_api_key=None)

        with pytest.raises(TypeError) as exc_info:
            await middleware(scope, _noop_receive, _noop_send)  # type: ignore[arg-type]

        frame_locals = _find_middleware_frame_locals(exc_info.value.__traceback__)

        assert frame_locals is not None, "traceback did not include APIKeyMiddleware.__call__'s frame"
        assert frame_locals.get("api_key") is None
        assert frame_locals.get("key_info") is None


class TestRevocationTimingIsDocumented:
    """Regression tests for the revocation-semantics finding.

    Guards check the ``APIKeyInfo`` snapshot ``APIKeyMiddleware`` captured at
    validation time, not the backend directly: a revoke()/scope change that
    lands after this middleware's ``backend.get()`` call but before the
    guard/handler for that same request finishes does not retroactively
    affect that in-flight request. That is standard request-scoped snapshot
    behavior, not a reusable bypass -- every request validated *after* the
    revocation lands is rejected as usual -- but it was previously
    undocumented, which risked API consumers assuming revocation takes effect
    instantly against requests already past this middleware.

    Before the fix, neither ``APIKeyMiddleware``'s nor
    ``get_api_key_info``'s docstrings said anything about this timing, so a
    reader had no way to learn the guarantee (or the lack of one) without
    reading the implementation.
    """

    def test_middleware_docstring_documents_revocation_timing(self) -> None:
        """``APIKeyMiddleware``'s docstring must disclose snapshot timing."""
        doc = APIKeyMiddleware.__doc__ or ""
        assert "Revocation timing" in doc
        assert "backend.get()" in doc

    def test_guard_docstring_documents_revocation_timing(self) -> None:
        """``get_api_key_info``'s docstring must disclose snapshot timing."""
        from litestar_api_auth.guards import get_api_key_info

        doc = get_api_key_info.__doc__ or ""
        assert "request-scoped snapshot" in doc

    async def test_concurrent_revocation_does_not_affect_in_flight_snapshot(self) -> None:
        """A revoke() that lands after backend.get() must not retroactively
        change the ``APIKeyInfo`` already handed to this request.

        Simulates the exact race from the finding: the raw key is validated
        (as if by the middleware, mid-request) *before* a concurrent
        request revokes it, and the already-obtained snapshot must still
        report the pre-revocation ``is_active=True`` -- while validating the
        *same* key again afterward (as a new request would) must now raise
        ``APIKeyRevokedError``, proving revocation is enforced going forward.
        """
        backend = MemoryBackend()
        raw_key, key_hash = generate_api_key(prefix="test_")
        await backend.create(
            key_hash,
            APIKeyInfo(key_id="good", key_hash=key_hash, name="Good", scopes=["read:users"]),
        )
        middleware = APIKeyMiddleware(app=_dummy_app, backend=backend)  # type: ignore[arg-type]

        # This request's middleware lookup happens first, mirroring
        # backend.get() completing before the concurrent revoke() below.
        in_flight_snapshot = await middleware._validate_api_key(raw_key)
        assert in_flight_snapshot.is_active is True

        # A concurrent request revokes the key while the first request is
        # still mid-flight (e.g. inside a guard or handler).
        revoked = await backend.revoke(key_hash)
        assert revoked is True

        # The snapshot already obtained by the in-flight request must be
        # unaffected -- it is a copy, not a live view of the backend record.
        assert in_flight_snapshot.is_active is True

        # Any request validated after the revocation lands -- including a
        # hypothetical retry of this same request -- must be rejected.
        with pytest.raises(APIKeyRevokedError):
            await middleware._validate_api_key(raw_key)

    async def test_guard_reads_pre_revocation_snapshot_through_full_middleware_call(self) -> None:
        """End-to-end version of the race, through ``APIKeyMiddleware.__call__``
        and ``guards.get_api_key_info`` (not ``_validate_api_key`` directly).

        The downstream ASGI app stands in for a guard followed by a handler:
        it reads ``request.state.api_key`` via ``get_api_key_info`` (as
        ``require_scope``/``require_scopes`` do), *then* a concurrent request
        revokes the key and drops one of its scopes, then the same downstream
        app reads ``get_api_key_info`` again to simulate the handler's own
        access later in the same request. Both reads, despite the revocation
        landing in between, must return the original active key with its
        original scopes -- proving the guarantee holds through the guard
        layer, not just at the ``_validate_api_key`` level. A fresh request
        for the same key afterward must then be rejected.
        """
        from litestar.connection import ASGIConnection
        from litestar.exceptions import NotAuthorizedException

        from litestar_api_auth.guards import get_api_key_info

        backend = MemoryBackend()
        raw_key, key_hash = generate_api_key(prefix="test_")
        await backend.create(
            key_hash,
            APIKeyInfo(key_id="good", key_hash=key_hash, name="Good", scopes=["read:users", "write:users"]),
        )

        observed: list[APIKeyInfo] = []

        async def _guard_then_handler(inner_scope: dict[str, Any], _receive: Any, _send: Any) -> None:
            connection = ASGIConnection(inner_scope)  # type: ignore[arg-type]

            # Guard-time read: the request is authenticated and in scope.
            observed.append(get_api_key_info(connection))

            # A concurrent request revokes this key and drops a scope while
            # *this* request is still executing past the guard.
            await backend.update(key_hash, scopes=["read:users"])
            await backend.revoke(key_hash)

            # Handler-time read, still within this same in-flight request.
            observed.append(get_api_key_info(connection))

        middleware = APIKeyMiddleware(app=_guard_then_handler, backend=backend)  # type: ignore[arg-type]
        scope = _make_scope(headers=[(b"x-api-key", raw_key.encode())], stale_api_key=None)

        await middleware(scope, _noop_receive, _noop_send)  # type: ignore[arg-type]

        assert len(observed) == 2
        for snapshot in observed:
            assert snapshot.is_active is True
            assert snapshot.scopes == ["read:users", "write:users"]

        # A brand new request for the same (now revoked) key must be
        # rejected by the middleware itself: state["api_key"] stays None, so
        # the same get_api_key_info() the downstream app calls now raises.
        second_scope = _make_scope(headers=[(b"x-api-key", raw_key.encode())], stale_api_key=None)
        with pytest.raises(NotAuthorizedException):
            await middleware(second_scope, _noop_receive, _noop_send)  # type: ignore[arg-type]
        assert second_scope["state"]["api_key"] is None
