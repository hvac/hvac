#!/usr/bin/env python
import time
import pytest
from threading import Thread
from hvac.token_cache import TokenCache


class TestTokenCache:
    """Unit tests for TokenCache class."""

    def test_init(self):
        """Test TokenCache initialization."""
        cache = TokenCache()
        assert cache.size() == 0

    def test_store_and_get(self):
        """Test storing and retrieving a token."""
        cache = TokenCache()
        cache.store(key="test_key", token="s.test_token", ttl=3600)

        token = cache.get("test_key")
        assert token == "s.test_token"

    def test_get_nonexistent_key(self):
        """Test getting a non-existent key returns None."""
        cache = TokenCache()
        token = cache.get("nonexistent")
        assert token is None

    def test_token_expiration(self):
        """Test that expired tokens are not returned."""
        cache = TokenCache()
        # Store token with 1 second TTL
        cache.store(key="expire_key", token="s.expire_token", ttl=1)

        # Token should be available immediately
        token = cache.get("expire_key")
        assert token == "s.expire_token"

        # Wait for expiration
        time.sleep(1.1)

        # Token should be expired and return None
        token = cache.get("expire_key")
        assert token is None

    def test_token_without_ttl(self):
        """Test that tokens without TTL never expire."""
        cache = TokenCache()
        cache.store(key="no_ttl_key", token="s.no_ttl_token", ttl=None)

        # Token should be available
        token = cache.get("no_ttl_key")
        assert token == "s.no_ttl_token"

        # Even after time passes, token should still be available
        time.sleep(0.1)
        token = cache.get("no_ttl_key")
        assert token == "s.no_ttl_token"

    def test_store_with_metadata(self):
        """Test storing token with metadata."""
        cache = TokenCache()
        metadata = {
            "accessor": "hmac-123",
            "policies": ["default", "admin"],
            "token_type": "service",
        }
        cache.store(
            key="meta_key",
            token="s.meta_token",
            ttl=3600,
            renewable=True,
            metadata=metadata,
        )

        token = cache.get("meta_key")
        assert token == "s.meta_token"

        stored_metadata = cache.get_metadata("meta_key")
        assert stored_metadata is not None
        assert stored_metadata["ttl"] == 3600
        assert stored_metadata["renewable"] is True
        assert stored_metadata["metadata"] == metadata

    def test_get_metadata_nonexistent(self):
        """Test getting metadata for non-existent key returns None."""
        cache = TokenCache()
        metadata = cache.get_metadata("nonexistent")
        assert metadata is None

    def test_get_metadata_expired(self):
        """Test that metadata is not returned for expired tokens."""
        cache = TokenCache()
        cache.store(key="expire_meta", token="s.token", ttl=1)

        # Metadata should be available
        metadata = cache.get_metadata("expire_meta")
        assert metadata is not None

        # Wait for expiration
        time.sleep(1.1)

        # Metadata should not be returned
        metadata = cache.get_metadata("expire_meta")
        assert metadata is None

    def test_invalidate(self):
        """Test invalidating a cached token."""
        cache = TokenCache()
        cache.store(key="invalid_key", token="s.invalid_token", ttl=3600)

        # Token should exist
        assert cache.get("invalid_key") is not None

        # Invalidate the token
        cache.invalidate("invalid_key")

        # Token should no longer exist
        assert cache.get("invalid_key") is None

    def test_invalidate_nonexistent(self):
        """Test invalidating a non-existent key doesn't raise an error."""
        cache = TokenCache()
        cache.invalidate("nonexistent")  # Should not raise

    def test_clear(self):
        """Test clearing all cached tokens."""
        cache = TokenCache()
        cache.store(key="key1", token="s.token1", ttl=3600)
        cache.store(key="key2", token="s.token2", ttl=3600)
        cache.store(key="key3", token="s.token3", ttl=3600)

        assert cache.size() == 3

        cache.clear()

        assert cache.size() == 0
        assert cache.get("key1") is None
        assert cache.get("key2") is None
        assert cache.get("key3") is None

    def test_size(self):
        """Test size method returns correct count."""
        cache = TokenCache()
        assert cache.size() == 0

        cache.store(key="key1", token="s.token1", ttl=3600)
        assert cache.size() == 1

        cache.store(key="key2", token="s.token2", ttl=3600)
        assert cache.size() == 2

        cache.invalidate("key1")
        assert cache.size() == 1

        cache.clear()
        assert cache.size() == 0

    def test_size_excludes_expired(self):
        """Test that size() excludes expired tokens."""
        cache = TokenCache()
        cache.store(key="key1", token="s.token1", ttl=1)
        cache.store(key="key2", token="s.token2", ttl=3600)

        assert cache.size() == 2

        # Wait for first token to expire
        time.sleep(1.1)

        # Size should now be 1 (expired token excluded)
        assert cache.size() == 1

    def test_thread_safety(self):
        """Test that cache operations are thread-safe."""
        cache = TokenCache()
        errors = []

        def store_tokens():
            try:
                for i in range(100):
                    cache.store(key=f"key_{i}", token=f"s.token_{i}", ttl=3600)
            except Exception as e:
                errors.append(e)

        def get_tokens():
            try:
                for i in range(100):
                    cache.get(f"key_{i}")
            except Exception as e:
                errors.append(e)

        # Create multiple threads
        threads = []
        for _ in range(5):
            threads.append(Thread(target=store_tokens))
            threads.append(Thread(target=get_tokens))

        # Start all threads
        for thread in threads:
            thread.start()

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

        # No errors should have occurred
        assert len(errors) == 0

    def test_overwrite_existing_key(self):
        """Test that storing with an existing key overwrites the old value."""
        cache = TokenCache()
        cache.store(key="overwrite", token="s.token1", ttl=3600)
        assert cache.get("overwrite") == "s.token1"

        cache.store(key="overwrite", token="s.token2", ttl=7200)
        assert cache.get("overwrite") == "s.token2"

        metadata = cache.get_metadata("overwrite")
        assert metadata["ttl"] == 7200
