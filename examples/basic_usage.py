"""Basic usage example for litestar-api-auth core functionality.

This example demonstrates the core API key generation, hashing, and validation
functionality without requiring a database or Litestar application.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from litestar_api_auth import (
    APIKeyInfo,
    APIKeyState,
    extract_key_id,
    generate_api_key,
    hash_api_key,
    verify_api_key,
)
from litestar_api_auth.exceptions import APIKeyExpiredError, InsufficientScopesError


def main() -> None:
    """Demonstrate basic API key operations."""
    print("=" * 60)
    print("Litestar API Auth - Basic Usage Example")
    print("=" * 60)

    # 1. Generate a new API key
    print("\n1. Generating a new API key...")
    raw_key, hashed_key = generate_api_key(prefix="demo_")
    print(f"   Raw key (show once): {raw_key}")
    print(f"   Hashed key (store): {hashed_key[:32]}...")

    # 2. Extract key ID for display
    print("\n2. Extracting key ID for display...")
    key_id = extract_key_id(raw_key)
    print(f"   Key ID: {key_id}")

    # 3. Verify the key
    print("\n3. Verifying the API key...")
    is_valid = verify_api_key(raw_key, hashed_key)
    print(f"   Verification result: {is_valid}")

    # 4. Try verifying with wrong key
    print("\n4. Testing with incorrect key...")
    wrong_key = "demo_WrongKeyData12345678901234567890123"
    is_valid = verify_api_key(wrong_key, hashed_key)
    print(f"   Verification result: {is_valid}")

    # 5. Create APIKeyInfo metadata
    print("\n5. Creating API key metadata...")
    key_info = APIKeyInfo(
        key_id=key_id or "unknown",
        prefix="demo_",
        name="Demo API Key",
        scopes=["read:users", "write:posts", "read:analytics"],
        created_at=datetime.utcnow(),
        expires_at=datetime.utcnow() + timedelta(days=365),
        is_active=True,
        metadata={"owner": "demo@example.com", "environment": "development"},
    )
    print(f"   Key ID: {key_info.key_id}")
    print(f"   Name: {key_info.name}")
    print(f"   Scopes: {', '.join(key_info.scopes)}")
    print(f"   State: {key_info.state.value}")
    print(f"   Is valid: {key_info.is_valid}")

    # 6. Check scopes
    print("\n6. Checking scopes...")
    print(f"   Has 'read:users': {key_info.has_scope('read:users')}")
    print(f"   Has 'admin:delete': {key_info.has_scope('admin:delete')}")

    print("\n   Checking multiple scopes (all):")
    has_all = key_info.has_scopes(["read:users", "write:posts"], requirement="all")
    print(f"   Has ['read:users', 'write:posts'] (all): {has_all}")

    print("\n   Checking multiple scopes (any):")
    has_any = key_info.has_scopes(
        ["read:users", "admin:delete"],
        requirement="any",
    )
    print(f"   Has ['read:users', 'admin:delete'] (any): {has_any}")

    # 7. Simulate scope validation
    print("\n7. Simulating scope validation...")
    required_scopes = ["read:users", "write:posts"]
    if key_info.has_scopes(required_scopes, requirement="all"):
        print(f"   Access granted: Has all required scopes {required_scopes}")
    else:
        print(f"   Access denied: Missing scopes from {required_scopes}")

    # 8. Test expired key
    print("\n8. Testing expired key behavior...")
    expired_key_info = APIKeyInfo(
        key_id="expired123",
        prefix="demo_",
        name="Expired API Key",
        scopes=["read:users"],
        created_at=datetime.utcnow() - timedelta(days=2),
        expires_at=datetime.utcnow() - timedelta(days=1),
        is_active=True,
    )
    print(f"   State: {expired_key_info.state.value}")
    print(f"   Is expired: {expired_key_info.is_expired}")
    print(f"   Is valid: {expired_key_info.is_valid}")

    # 9. Test revoked key
    print("\n9. Testing revoked key behavior...")
    revoked_key_info = APIKeyInfo(
        key_id="revoked123",
        prefix="demo_",
        name="Revoked API Key",
        scopes=["read:users"],
        created_at=datetime.utcnow(),
        is_active=False,
    )
    print(f"   State: {revoked_key_info.state.value}")
    print(f"   Is active: {revoked_key_info.is_active}")
    print(f"   Is valid: {revoked_key_info.is_valid}")

    # 10. Exception handling
    print("\n10. Testing exception handling...")
    try:
        if expired_key_info.is_expired:
            raise APIKeyExpiredError(
                key_id=expired_key_info.key_id,
                expired_at=expired_key_info.expires_at,
            )
    except APIKeyExpiredError as e:
        print(f"   Caught exception: {e}")

    try:
        if not key_info.has_scopes(["admin:write"], requirement="all"):
            raise InsufficientScopesError(
                required_scopes=["admin:write"],
                provided_scopes=key_info.scopes,
            )
    except InsufficientScopesError as e:
        print(f"   Caught exception: {e}")

    print("\n" + "=" * 60)
    print("Example completed successfully!")
    print("=" * 60)


if __name__ == "__main__":
    main()
