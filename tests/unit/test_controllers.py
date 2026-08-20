"""Unit tests for APIKeyController.

These tests exercise ``APIKeyController.create_api_key`` directly (via the
handler's underlying function) rather than through a full Litestar app, so
that raised exceptions -- and the traceback frames they carry -- can be
inspected precisely.
"""

from __future__ import annotations

from types import TracebackType
from typing import Any

import pytest

from litestar_api_auth.backends.base import APIKeyInfo
from litestar_api_auth.controllers import APIKeyController, CreateAPIKeyRequest

# The decorated handler's original coroutine function, unbound -- calling it
# directly (with an explicit `self`) avoids going through Litestar's routing
# layer, which isn't needed here and would obscure the traceback we assert on.
_create_api_key = APIKeyController.create_api_key.fn


class _ExplodingBackend:
    """Backend whose ``create()`` always raises, to exercise the error path
    of ``create_api_key`` without touching real storage."""

    async def create(self, key_hash: str, info: APIKeyInfo) -> APIKeyInfo:
        raise RuntimeError("backend unavailable")


def _find_frame_locals(tb: TracebackType | None, co_name: str) -> dict[str, Any] | None:
    """Walk a traceback and return the locals of the first frame whose code
    object has the given name, or None if no such frame is found."""
    while tb is not None:
        if tb.tb_frame.f_code.co_name == co_name:
            return tb.tb_frame.f_locals
        tb = tb.tb_next
    return None


class TestPlaintextKeyScrubbedFromLocalsOnBackendError:
    """Regression test: the raw plaintext bearer key generated in
    ``create_api_key`` must not remain in that frame's locals if
    ``backend.create()`` raises.

    Before the fix, ``plaintext_key``/``key_hash``/``key_info`` stayed live
    frame locals for as long as the resulting exception's traceback was held,
    so a monitoring tool that captures frame locals on unhandled exceptions
    (e.g. Sentry with ``include_local_variables=True``) could recover the
    raw bearer key straight out of the traceback -- this was the only place
    in the library where the *raw* key (not just its hash) was reachable
    that way. After the fix, this frame's locals are scrubbed before the
    exception propagates.
    """

    async def test_create_api_key_scrubs_locals_on_backend_error(self) -> None:
        controller = APIKeyController(owner=None)  # type: ignore[arg-type]
        data = CreateAPIKeyRequest(name="test key")

        with pytest.raises(RuntimeError, match="backend unavailable") as exc_info:
            await _create_api_key(controller, data=data, backend=_ExplodingBackend())

        frame_locals = _find_frame_locals(exc_info.value.__traceback__, "create_api_key")

        assert frame_locals is not None, "traceback did not include create_api_key's frame"
        assert frame_locals.get("plaintext_key") is None
        assert frame_locals.get("key_hash") is None
        assert frame_locals.get("key_info") is None
