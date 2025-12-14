"""Unit tests for API key generation and validation service."""

from __future__ import annotations

import re

import pytest

from litestar_api_auth.exceptions import InvalidAPIKeyError
from litestar_api_auth.service import (
    extract_key_id,
    generate_api_key,
    hash_api_key,
    verify_api_key,
)


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

        assert key_id == "AbCdEfGh"

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

        # Should split on first underscore only
        assert key_id == "app_AbCd"

    def test_extracts_from_generated_key(self) -> None:
        """Test extraction from a generated key."""
        raw_key, _ = generate_api_key(prefix="test_")
        key_id = extract_key_id(raw_key)

        assert key_id is not None
        assert len(key_id) == 8
        assert key_id == raw_key[5:13]  # After "test_", first 8 chars
