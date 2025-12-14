"""Quickstart example demonstrating core functionality.

This minimal example shows the essential features of the litestar-api-auth
core service and types.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from litestar_api_auth import (
    APIKeyInfo,
    generate_api_key,
    verify_api_key,
)


# 1. Generate a new API key
raw_key, hashed_key = generate_api_key(prefix="demo_")
print(f"Generated key: {raw_key}")
print(f"Hashed (store this): {hashed_key[:32]}...\n")

# 2. Verify the key
is_valid = verify_api_key(raw_key, hashed_key)
print(f"Key verification: {is_valid}\n")

# 3. Create API key metadata
key_info = APIKeyInfo(
    key_id="demo123",
    prefix="demo_",
    name="Demo API Key",
    scopes=["read:users", "write:posts"],
    created_at=datetime.now(timezone.utc),
    expires_at=datetime.now(timezone.utc) + timedelta(days=365),
    is_active=True,
)

# 4. Check key status
print(f"Key state: {key_info.state.value}")
print(f"Is valid: {key_info.is_valid}")
print(f"Is expired: {key_info.is_expired}\n")

# 5. Check scopes
print(f"Has 'read:users': {key_info.has_scope('read:users')}")
print(f"Has all ['read:users', 'write:posts']: {key_info.has_scopes(['read:users', 'write:posts'], requirement='all')}")
