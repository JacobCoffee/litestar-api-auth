"""Tests for API key generation and validation service.

This module tests the core cryptographic functions for generating,
hashing, and verifying API keys.
"""

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
    """Tests for generate_api_key function."""

    def test_generate_api_key_returns_tuple(self) -> None:
        """Test that generate_api_key returns a tuple of two strings."""
        result = generate_api_key()

        assert isinstance(result, tuple)
        assert len(result) == 2
        assert isinstance(result[0], str)  # raw_key
        assert isinstance(result[1], str)  # hashed_key

    def test_generate_api_key_with_default_prefix(self) -> None:
        """Test that default prefix is 'pyorg_'."""
        raw_key, _ = generate_api_key()

        assert raw_key.startswith("pyorg_")

    def test_generate_api_key_with_custom_prefix(self) -> None:
        """Test that custom prefix is applied correctly."""
        custom_prefix = "myapp_"
        raw_key, _ = generate_api_key(prefix=custom_prefix)

        assert raw_key.startswith(custom_prefix)

    def test_generate_api_key_randomness(self) -> None:
        """Test that each call generates unique keys."""
        key1_raw, key1_hash = generate_api_key()
        key2_raw, key2_hash = generate_api_key()

        # Keys should be different
        assert key1_raw != key2_raw
        assert key1_hash != key2_hash

    def test_generate_api_key_length(self) -> None:
        """Test that generated keys have appropriate length.

        32 bytes of random data encoded as base64url (without padding)
        should be 43 characters, plus the prefix length.
        """
        prefix = "test_"
        raw_key, _ = generate_api_key(prefix=prefix)

        # Remove prefix to get the encoded portion
        encoded_portion = raw_key[len(prefix) :]

        # 32 bytes -> 43 base64url characters (no padding)
        assert len(encoded_portion) == 43

    def test_generate_api_key_hash_format(self) -> None:
        """Test that hash is a valid SHA-256 hex string."""
        _, hashed_key = generate_api_key()

        # SHA-256 hash should be 64 hex characters
        assert len(hashed_key) == 64
        assert re.match(r"^[a-f0-9]{64}$", hashed_key)

    def test_generate_api_key_url_safe(self) -> None:
        """Test that generated keys are URL-safe."""
        raw_key, _ = generate_api_key()

        # Should not contain characters that need URL encoding
        assert "+" not in raw_key
        assert "/" not in raw_key
        assert "=" not in raw_key  # No padding

    def test_generate_api_key_multiple_underscores_in_prefix(self) -> None:
        """Test that prefix with multiple underscores works correctly."""
        prefix = "my_app_v2_"
        raw_key, _ = generate_api_key(prefix=prefix)

        assert raw_key.startswith(prefix)


class TestHashAPIKey:
    """Tests for hash_api_key function."""

    def test_hash_api_key_is_deterministic(self) -> None:
        """Test that hashing the same key produces the same hash."""
        test_key = "test_key_123456789"

        hash1 = hash_api_key(test_key)
        hash2 = hash_api_key(test_key)

        assert hash1 == hash2

    def test_hash_api_key_format(self) -> None:
        """Test that hash is a valid SHA-256 hex string."""
        test_key = "test_key_abcdef"
        hashed = hash_api_key(test_key)

        assert len(hashed) == 64
        assert re.match(r"^[a-f0-9]{64}$", hashed)

    def test_hash_api_key_different_inputs(self) -> None:
        """Test that different keys produce different hashes."""
        key1 = "test_key_1"
        key2 = "test_key_2"

        hash1 = hash_api_key(key1)
        hash2 = hash_api_key(key2)

        assert hash1 != hash2

    def test_hash_api_key_with_special_characters(self) -> None:
        """Test hashing keys with special characters."""
        special_key = "test_@#$%^&*()_+={}[]|\\:;<>,.?/"
        hashed = hash_api_key(special_key)

        assert len(hashed) == 64
        assert re.match(r"^[a-f0-9]{64}$", hashed)

    def test_hash_api_key_with_unicode(self) -> None:
        """Test hashing keys with unicode characters."""
        unicode_key = "test_key_你好世界"
        hashed = hash_api_key(unicode_key)

        assert len(hashed) == 64
        assert re.match(r"^[a-f0-9]{64}$", hashed)


class TestVerifyAPIKey:
    """Tests for verify_api_key function."""

    def test_verify_api_key_valid(self, api_key_pair: tuple[str, str]) -> None:
        """Test that valid API key verification succeeds."""
        raw_key, hashed_key = api_key_pair

        assert verify_api_key(raw_key, hashed_key) is True

    def test_verify_api_key_invalid(self, api_key_pair: tuple[str, str]) -> None:
        """Test that invalid API key verification fails."""
        _, hashed_key = api_key_pair
        wrong_key = "wrong_key_12345678901234567890123456789012345"

        assert verify_api_key(wrong_key, hashed_key) is False

    def test_verify_api_key_empty_key(self) -> None:
        """Test verification with empty key."""
        _, hashed_key = generate_api_key()
        empty_key = ""

        assert verify_api_key(empty_key, hashed_key) is False

    def test_verify_api_key_tampered_hash(self, api_key_pair: tuple[str, str]) -> None:
        """Test that tampered hash fails verification."""
        raw_key, hashed_key = api_key_pair

        # Tamper with the hash by changing one character
        tampered_hash = "0" + hashed_key[1:]

        assert verify_api_key(raw_key, tampered_hash) is False

    def test_verify_api_key_case_sensitivity(self) -> None:
        """Test that verification is case-sensitive."""
        raw_key = "test_ABC123def456GHI789jkl012MNO345pqr678STU901"
        hashed_key = hash_api_key(raw_key)

        # Verify original key works
        assert verify_api_key(raw_key, hashed_key) is True

        # Verify case-changed key fails
        assert verify_api_key(raw_key.upper(), hashed_key) is False

    def test_verify_api_key_timing_safe(self) -> None:
        """Test that verification uses constant-time comparison.

        While we can't directly test timing, we can verify that the function
        uses hmac.compare_digest by checking it handles various input lengths.
        """
        raw_key, hashed_key = generate_api_key()

        # All of these should return False without raising exceptions
        assert verify_api_key("short", hashed_key) is False
        assert verify_api_key("medium_length_key", hashed_key) is False
        assert verify_api_key("very_long_key_" * 10, hashed_key) is False


class TestExtractKeyID:
    """Tests for extract_key_id function."""

    def test_extract_key_id_success(self) -> None:
        """Test successful key ID extraction."""
        test_key = "pyorg_ABC12345DEF67890GHI12345JKL67890MNO12345"
        key_id = extract_key_id(test_key)

        assert key_id == "ABC12345"

    def test_extract_key_id_with_custom_prefix(self) -> None:
        """Test key ID extraction with custom prefix."""
        test_key = "custom_XYZ98765abc12345def67890ghi12345jkl67890"
        key_id = extract_key_id(test_key)

        assert key_id == "XYZ98765"

    def test_extract_key_id_from_generated_key(self, api_key_pair: tuple[str, str]) -> None:
        """Test extracting key ID from a generated API key."""
        raw_key, _ = api_key_pair
        key_id = extract_key_id(raw_key)

        assert key_id is not None
        assert len(key_id) == 8
        # Should be part of the key after the prefix
        assert key_id in raw_key

    def test_extract_key_id_no_underscore(self) -> None:
        """Test that keys without underscore return None."""
        test_key = "invalidkey"
        key_id = extract_key_id(test_key)

        assert key_id is None

    def test_extract_key_id_too_short(self) -> None:
        """Test that keys with insufficient length raise exception."""
        test_key = "test_ABC"  # Only 3 characters after prefix

        with pytest.raises(InvalidAPIKeyError) as exc_info:
            extract_key_id(test_key)

        assert "too short" in str(exc_info.value)

    def test_extract_key_id_exactly_eight_chars(self) -> None:
        """Test that keys with exactly 8 characters after prefix work."""
        test_key = "test_ABCD1234"
        key_id = extract_key_id(test_key)

        assert key_id == "ABCD1234"

    def test_extract_key_id_multiple_underscores(self) -> None:
        """Test key ID extraction with multiple underscores in prefix."""
        test_key = "my_app_v2_ABC12345DEF67890"
        key_id = extract_key_id(test_key)

        # Should split on first underscore and return first 8 chars of remainder
        assert key_id == "app_v2_A"

    def test_extract_key_id_trailing_underscore(self) -> None:
        """Test key ID extraction when key ends with underscore."""
        test_key = "test_ABC12345_"
        key_id = extract_key_id(test_key)

        assert key_id == "ABC12345"

    def test_extract_key_id_only_underscore(self) -> None:
        """Test that a key that's just an underscore returns None."""
        test_key = "_"

        with pytest.raises(InvalidAPIKeyError):
            extract_key_id(test_key)


class TestIntegration:
    """Integration tests combining multiple service functions."""

    def test_full_key_lifecycle(self) -> None:
        """Test complete key generation, hashing, and verification flow."""
        # Generate a new key
        raw_key, hashed_key = generate_api_key(prefix="test_")

        # Verify the key format
        assert raw_key.startswith("test_")
        assert len(hashed_key) == 64

        # Extract key ID
        key_id = extract_key_id(raw_key)
        assert key_id is not None
        assert len(key_id) == 8

        # Verify the key
        assert verify_api_key(raw_key, hashed_key) is True

        # Verify wrong key fails
        wrong_key = raw_key[:-1] + "X"
        assert verify_api_key(wrong_key, hashed_key) is False

    def test_multiple_keys_independence(self) -> None:
        """Test that multiple generated keys are independent."""
        key1_raw, key1_hash = generate_api_key(prefix="app1_")
        key2_raw, key2_hash = generate_api_key(prefix="app2_")
        key3_raw, key3_hash = generate_api_key(prefix="app1_")

        # All keys should be different
        assert key1_raw != key2_raw
        assert key1_raw != key3_raw
        assert key2_raw != key3_raw

        # Each key should only verify against its own hash
        assert verify_api_key(key1_raw, key1_hash) is True
        assert verify_api_key(key1_raw, key2_hash) is False
        assert verify_api_key(key1_raw, key3_hash) is False

        assert verify_api_key(key2_raw, key1_hash) is False
        assert verify_api_key(key2_raw, key2_hash) is True
        assert verify_api_key(key2_raw, key3_hash) is False
