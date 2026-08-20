"""Unit tests for API key generation and validation service."""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from litestar_api_auth.backends.base import APIKeyInfo as BackendAPIKeyInfo
from litestar_api_auth.backends.memory import MemoryBackend
from litestar_api_auth.exceptions import InvalidAPIKeyError
from litestar_api_auth.middleware import APIKeyMiddleware
from litestar_api_auth.service import (
    extract_key_id,
    generate_api_key,
    hash_api_key,
    mint_api_key,
    verify_api_key,
)
from litestar_api_auth.types import APIKeyInfo as PublicAPIKeyInfo


async def _mint_dummy_app(_scope: dict[str, Any], _receive: Any, _send: Any) -> None:
    """Minimal downstream ASGI app used by the middleware round-trip test."""
    return


async def _mint_noop_receive() -> dict[str, Any]:
    return {"type": "http.request", "body": b"", "more_body": False}


async def _mint_noop_send(_message: dict[str, Any]) -> None:
    return None


class TestGenerateAPIKey:
    """Test suite for generate_api_key function."""

    def test_generates_key_with_default_prefix(self) -> None:
        """Test that key generation uses default prefix."""
        raw_key, hashed_key = generate_api_key()

        assert raw_key.startswith("pyorg_")
        assert len(hashed_key) == 64  # SHA-256 produces 64 hex chars
        assert isinstance(raw_key, str)
        assert isinstance(hashed_key, str)

    def test_generates_key_with_custom_prefix(self) -> None:
        """Test that key generation uses custom prefix."""
        custom_prefix = "myapp_"
        raw_key, hashed_key = generate_api_key(prefix=custom_prefix)

        assert raw_key.startswith(custom_prefix)
        assert len(hashed_key) == 64

    def test_generates_unique_keys(self) -> None:
        """Test that multiple calls generate different keys."""
        key1, hash1 = generate_api_key()
        key2, hash2 = generate_api_key()

        assert key1 != key2
        assert hash1 != hash2

    def test_generated_key_format(self) -> None:
        """Test that generated keys have expected format."""
        raw_key, _ = generate_api_key(prefix="test_")

        # Should be prefix + base64url characters (no padding)
        pattern = r"^test_[A-Za-z0-9_-]+$"
        assert re.match(pattern, raw_key)

        # Key portion should be from 32 bytes = 43 chars in base64url (no padding)
        key_portion = raw_key[5:]  # Remove "test_"
        assert len(key_portion) == 43

    def test_raw_key_matches_hash(self) -> None:
        """Test that raw key can be verified against its hash."""
        raw_key, hashed_key = generate_api_key()

        assert verify_api_key(raw_key, hashed_key)


class TestHashAPIKey:
    """Test suite for hash_api_key function."""

    def test_produces_consistent_hash(self) -> None:
        """Test that hashing the same key produces the same hash."""
        key = "pyorg_test123456"
        hash1 = hash_api_key(key)
        hash2 = hash_api_key(key)

        assert hash1 == hash2

    def test_produces_different_hashes_for_different_keys(self) -> None:
        """Test that different keys produce different hashes."""
        key1 = "pyorg_test123456"
        key2 = "pyorg_test654321"

        hash1 = hash_api_key(key1)
        hash2 = hash_api_key(key2)

        assert hash1 != hash2

    def test_hash_length(self) -> None:
        """Test that hash is 64 characters (SHA-256 in hex)."""
        key = "pyorg_test123456"
        key_hash = hash_api_key(key)

        assert len(key_hash) == 64
        assert all(c in "0123456789abcdef" for c in key_hash)


class TestVerifyAPIKey:
    """Test suite for verify_api_key function."""

    def test_verifies_correct_key(self) -> None:
        """Test that correct key passes verification."""
        raw_key = "pyorg_AbCdEfGh123456789012345678901234567890"
        hashed_key = hash_api_key(raw_key)

        assert verify_api_key(raw_key, hashed_key)

    def test_rejects_incorrect_key(self) -> None:
        """Test that incorrect key fails verification."""
        raw_key = "pyorg_AbCdEfGh123456789012345678901234567890"
        wrong_key = "pyorg_WrongKey123456789012345678901234567"
        hashed_key = hash_api_key(raw_key)

        assert not verify_api_key(wrong_key, hashed_key)

    def test_rejects_tampered_hash(self) -> None:
        """Test that tampered hash fails verification."""
        raw_key = "pyorg_AbCdEfGh123456789012345678901234567890"
        hashed_key = hash_api_key(raw_key)
        tampered_hash = "0" + hashed_key[1:]  # Change first character

        assert not verify_api_key(raw_key, tampered_hash)


class TestExtractKeyID:
    """Test suite for extract_key_id function."""

    def test_extracts_id_from_valid_key(self) -> None:
        """Test extraction of key ID from valid API key."""
        raw_key = "pyorg_AbCdEfGh123456789012345678901234567890"
        key_id = extract_key_id(raw_key)

        assert key_id == hash_api_key(raw_key)[:8]

    def test_returns_none_for_key_without_underscore(self) -> None:
        """Test that keys without underscore return None."""
        invalid_key = "pyorgAbCdEfGh123456789012345678901234567890"
        key_id = extract_key_id(invalid_key)

        assert key_id is None

    def test_raises_for_too_short_key(self) -> None:
        """Test that too-short keys raise an error."""
        short_key = "pyorg_Abc"

        with pytest.raises(InvalidAPIKeyError) as exc_info:
            extract_key_id(short_key)

        assert "too short" in str(exc_info.value).lower()

    def test_handles_multiple_underscores(self) -> None:
        """Test that keys with multiple underscores work correctly."""
        raw_key = "my_app_AbCdEfGh123456789012345678901234567890"
        key_id = extract_key_id(raw_key)

        # Should split on first underscore only, and hash the full raw key
        assert key_id == hash_api_key(raw_key)[:8]

    def test_extracts_from_generated_key(self) -> None:
        """Test extraction from a generated key."""
        raw_key, _ = generate_api_key(prefix="test_")
        key_id = extract_key_id(raw_key)

        assert key_id is not None
        assert len(key_id) == 8
        assert key_id == hash_api_key(raw_key)[:8]

    def test_key_id_does_not_expose_key_material(self) -> None:
        """Regression test: key_id must not leak characters of the secret.

        Previously extract_key_id() returned the first 8 characters of the
        key's random portion verbatim, so logging the "safe" identifier per
        the docstring's own advice leaked 48 bits of the secret. The
        identifier must now be derived from a hash of the key, independent
        of the key's literal characters.
        """
        # Fixed (not randomly generated) key so this assertion is
        # deterministic rather than merely astronomically unlikely to flake.
        raw_key = "test_AbCdEfGh123456789012345678901234567890"
        key_portion = raw_key.split("_", 1)[1]
        key_id = extract_key_id(raw_key)

        assert key_id is not None
        # The old vulnerable behavior: key_id was a verbatim substring of the
        # secret. That must no longer be true.
        assert key_id != key_portion[:8]
        # The identifier should instead match the hash-derived value.
        assert key_id == hash_api_key(raw_key)[:8]


class TestMintAPIKey:
    """Test suite for the ``mint_api_key`` helper.

    This is the one call a host application's "mint a key" flow should need:
    before it existed, ``generate_api_key`` returned only
    ``(plaintext, hash)`` and every caller had to build a ``key_id``, assemble
    an ``APIKeyInfo`` by hand and remember to call ``backend.create()``.
    """

    async def test_persists_key_and_returns_plaintext(self) -> None:
        """The minted key must be usable to look the record back up."""
        backend = MemoryBackend()

        plaintext, info = await mint_api_key(
            backend,
            name="Reporting job",
            scopes=["reports:read"],
            prefix="pycon_",
        )

        assert plaintext.startswith("pycon_")
        assert info.key_hash == hash_api_key(plaintext)
        assert info.name == "Reporting job"
        assert info.scopes == ["reports:read"]
        assert info.prefix == "pycon_"
        assert info.is_active is True
        assert info.created_at is not None

        stored = await backend.get(hash_api_key(plaintext))
        assert stored is not None
        assert stored.key_id == info.key_id
        assert stored.prefix == "pycon_"

    async def test_generates_a_key_id(self) -> None:
        """A ``key_id`` must be generated per key, not left to the caller."""
        backend = MemoryBackend()

        _, first = await mint_api_key(backend, name="a", scopes=[], prefix="test_")
        _, second = await mint_api_key(backend, name="b", scopes=[], prefix="test_")

        assert first.key_id
        assert second.key_id
        assert first.key_id != second.key_id

    async def test_returns_the_canonical_struct(self) -> None:
        """The returned record must be the struct backends/middleware use."""
        backend = MemoryBackend()

        _, info = await mint_api_key(backend, name="a", scopes=[], prefix="test_")

        assert isinstance(info, BackendAPIKeyInfo)
        assert isinstance(info, PublicAPIKeyInfo)

    async def test_passes_through_expiry_and_metadata(self) -> None:
        """Optional expiry/metadata must reach the stored record."""
        backend = MemoryBackend()
        expires_at = datetime.now(timezone.utc) + timedelta(days=30)

        plaintext, info = await mint_api_key(
            backend,
            name="Expiring",
            scopes=["read"],
            prefix="test_",
            expires_at=expires_at,
            metadata={"owner": "someone@example.com"},
        )

        assert info.expires_at == expires_at
        assert info.metadata == {"owner": "someone@example.com"}

        stored = await backend.get(hash_api_key(plaintext))
        assert stored is not None
        assert stored.metadata == {"owner": "someone@example.com"}

    async def test_minted_key_authenticates_through_the_middleware(self) -> None:
        """End-to-end: a minted key must satisfy the middleware it is meant for.

        This is the property manual hash/struct assembly in host code tends to
        break (hashing with a different scheme than the middleware verifies
        against).
        """
        backend = MemoryBackend()
        plaintext, info = await mint_api_key(backend, name="Live", scopes=["read"], prefix="test_")

        middleware = APIKeyMiddleware(app=_mint_dummy_app, backend=backend)  # type: ignore[arg-type]
        scope: dict[str, Any] = {
            "type": "http",
            "headers": [(b"x-api-key", plaintext.encode())],
            "state": {},
        }

        await middleware(scope, _mint_noop_receive, _mint_noop_send)  # type: ignore[arg-type]

        assert scope["state"]["api_key"] is not None
        assert scope["state"]["api_key"].key_id == info.key_id

    async def test_scrubs_key_material_when_backend_create_fails(self) -> None:
        """A backend error must not leave the plaintext key in frame locals.

        Mirrors ``APIKeyController.create_api_key``: a monitoring tool that
        captures frame locals on unhandled exceptions must not be able to
        recover the plaintext bearer key from the traceback.
        """
        backend = MemoryBackend()

        async def exploding_create(_key_hash: str, _info: object) -> None:
            raise RuntimeError("backend down")

        backend.create = exploding_create  # type: ignore[method-assign]

        frame_locals: dict[str, Any] | None = None

        try:
            await mint_api_key(backend, name="Doomed", scopes=[], prefix="test_")
        except RuntimeError as exc:
            walk = exc.__traceback__
            while walk is not None:
                if walk.tb_frame.f_code.co_name == "mint_api_key":
                    frame_locals = walk.tb_frame.f_locals
                    break
                walk = walk.tb_next

        assert frame_locals is not None
        assert frame_locals["plaintext_key"] == ""
        assert frame_locals["key_hash"] == ""
        assert frame_locals["info"] is None

    async def test_calls_backend_create_with_the_hash_and_record(self) -> None:
        """``backend.create()`` must receive the key hash and the built record.

        Pins the contract a custom backend sees, including the ``key_id``
        length produced by ``secrets.token_urlsafe(16)``.
        """
        calls: list[tuple[str, PublicAPIKeyInfo]] = []

        class RecordingBackend:
            async def create(self, key_hash: str, info: PublicAPIKeyInfo) -> PublicAPIKeyInfo:
                calls.append((key_hash, info))
                return info

        plaintext, info = await mint_api_key(
            RecordingBackend(),  # type: ignore[arg-type]
            name="Recorded",
            scopes=["read"],
            prefix="test_",
        )

        assert len(calls) == 1
        recorded_hash, recorded_info = calls[0]
        assert recorded_hash == hash_api_key(plaintext)
        assert recorded_info.key_hash == recorded_hash
        assert recorded_info is info
        # secrets.token_urlsafe(16) -> 22 base64url characters.
        assert len(info.key_id) == 22

    async def test_prefix_is_restored_when_a_backend_drops_it(self) -> None:
        """A backend that cannot persist ``prefix`` must not lose it for the caller."""

        class PrefixDroppingBackend:
            async def create(self, key_hash: str, info: PublicAPIKeyInfo) -> PublicAPIKeyInfo:
                return PublicAPIKeyInfo(
                    key_id=info.key_id,
                    name=info.name,
                    scopes=info.scopes,
                    key_hash=info.key_hash,
                )

        _, info = await mint_api_key(
            PrefixDroppingBackend(),  # type: ignore[arg-type]
            name="Dropped",
            scopes=[],
            prefix="test_",
        )

        assert info.prefix == "test_"

    async def test_backend_returning_none_falls_back_to_the_built_record(self) -> None:
        """A backend whose create() returns None must still yield a record."""

        class NoneReturningBackend:
            async def create(self, key_hash: str, info: PublicAPIKeyInfo) -> None:
                return None

        plaintext, info = await mint_api_key(
            NoneReturningBackend(),  # type: ignore[arg-type]
            name="Nothing",
            scopes=["read"],
            prefix="test_",
        )

        assert info.key_hash == hash_api_key(plaintext)
        assert info.prefix == "test_"
