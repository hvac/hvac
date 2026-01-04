"""
Token Cache for storing Vault authentication tokens with TTL awareness.
"""
import time
import threading
from typing import Optional, Dict, Any


class TokenCache:
    """In-memory cache for Vault tokens with TTL-based expiration.

    This class provides thread-safe storage and retrieval of Vault tokens
    with automatic expiration based on token TTL (time-to-live).
    """

    def __init__(self):
        """Initialize a new TokenCache instance."""
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.RLock()

    def store(
        self,
        key: str,
        token: str,
        ttl: Optional[int] = None,
        renewable: bool = False,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        """Store a token in the cache.

        :param key: Cache key (typically role_id or auth method identifier).
        :type key: str
        :param token: The Vault client token to cache.
        :type token: str
        :param ttl: Time-to-live in seconds. If None, token never expires.
        :type ttl: int | None
        :param renewable: Whether the token is renewable.
        :type renewable: bool
        :param metadata: Additional metadata to store with the token.
        :type metadata: dict | None
        """
        with self._lock:
            expiration = None
            if ttl is not None:
                expiration = time.time() + ttl

            self._cache[key] = {
                "token": token,
                "ttl": ttl,
                "expiration": expiration,
                "renewable": renewable,
                "metadata": metadata or {},
                "stored_at": time.time(),
            }

    def get(self, key: str) -> Optional[str]:
        """Retrieve a token from the cache if it exists and is not expired.

        :param key: Cache key to lookup.
        :type key: str
        :return: The cached token if valid, None otherwise.
        :rtype: str | None
        """
        with self._lock:
            cached = self._cache.get(key)
            if cached is None:
                return None

            # Check if token has expired
            if cached["expiration"] is not None:
                if time.time() >= cached["expiration"]:
                    # Token expired, remove from cache
                    del self._cache[key]
                    return None

            return cached["token"]

    def get_metadata(self, key: str) -> Optional[Dict[str, Any]]:
        """Retrieve metadata for a cached token.

        :param key: Cache key to lookup.
        :type key: str
        :return: Metadata dictionary if token exists and is valid, None otherwise.
        :rtype: dict | None
        """
        with self._lock:
            cached = self._cache.get(key)
            if cached is None:
                return None

            # Check expiration
            if cached["expiration"] is not None:
                if time.time() >= cached["expiration"]:
                    del self._cache[key]
                    return None

            return {
                "ttl": cached["ttl"],
                "renewable": cached["renewable"],
                "expiration": cached["expiration"],
                "stored_at": cached["stored_at"],
                "metadata": cached["metadata"],
            }

    def invalidate(self, key: str):
        """Remove a token from the cache.

        :param key: Cache key to invalidate.
        :type key: str
        """
        with self._lock:
            self._cache.pop(key, None)

    def clear(self):
        """Clear all tokens from the cache."""
        with self._lock:
            self._cache.clear()

    def size(self) -> int:
        """Return the number of cached tokens.

        :return: Number of tokens currently in cache.
        :rtype: int
        """
        with self._lock:
            # Clean up expired tokens first
            expired_keys = []
            current_time = time.time()
            for key, cached in self._cache.items():
                if cached["expiration"] is not None:
                    if current_time >= cached["expiration"]:
                        expired_keys.append(key)

            for key in expired_keys:
                del self._cache[key]

            return len(self._cache)
