"""Unit tests for APIKeyMiddleware.

These tests exercise APIKeyMiddleware.__call__ directly against a raw ASGI
scope, without going through a full Litestar app, so that scope["state"]
can be inspected precisely.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from litestar_api_auth.backends.base import APIKeyInfo
from litestar_api_auth.backends.memory import MemoryBackend
from litestar_api_auth.exceptions import APIKeyExpiredError, APIKeyRevokedError
from litestar_api_auth.middleware import APIKeyMiddleware
from litestar_api_auth.service import generate_api_key


async def _dummy_app(_scope: dict[str, Any], _receive: Any, _send: Any) -> None:
    """Minimal downstream ASGI app that does nothing."""
    return


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


class TestUpdateLastUsedRevocationRaceIsNotSwallowed:
    """Regression tests for the revocation-race finding.

    Before the fix, ``update_last_used()`` ran inside the same try block that
    caught ``APIKeyRevokedError``/``APIKeyExpiredError`` from validation, and
    by the time it ran, ``state["api_key"]`` had already been populated. A
    race-aware custom backend raising either exception from
    ``update_last_used()`` (e.g. after detecting a concurrent revocation) was
    silently swallowed, and the just-revoked/expired key's request reached
    guarded handlers still authenticated.
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
