"""
IntelBot Response Cache
In-memory cache with TTL to reduce API calls
"""
import time
from threading import Lock
from collections import OrderedDict


class ResponseCache:
    """
    Thread-safe in-memory cache with Time-To-Live (TTL).
    Uses LRU eviction when max size is reached.
    """

    def __init__(self, max_size=500, default_ttl=300):
        """
        Initialize cache.

        Args:
            max_size: Maximum number of cached items (default: 500)
            default_ttl: Default time-to-live in seconds (default: 300 = 5 minutes)
        """
        self.cache = OrderedDict()
        self.max_size = max_size
        self.default_ttl = default_ttl
        self.lock = Lock()
        self.stats = {
            "hits": 0,
            "misses": 0,
            "evictions": 0,
            "sets": 0
        }

    def _is_expired(self, entry):
        """Check if cache entry has expired."""
        return time.time() > entry["expires_at"]

    def get(self, key):
        """
        Retrieve value from cache.

        Args:
            key: Cache key

        Returns:
            Cached value or None if not found/expired
        """
        with self.lock:
            if key in self.cache:
                entry = self.cache[key]

                # Check expiration
                if self._is_expired(entry):
                    del self.cache[key]
                    self.stats["misses"] += 1
                    return None

                # Move to end (most recently used)
                self.cache.move_to_end(key)
                self.stats["hits"] += 1
                return entry["value"]

            self.stats["misses"] += 1
            return None

    def set(self, key, value, ttl=None):
        """
        Store value in cache.

        Args:
            key: Cache key
            value: Value to cache
            ttl: Time-to-live in seconds (uses default if None)
        """
        with self.lock:
            if ttl is None:
                ttl = self.default_ttl

            # Evict oldest entry if at max capacity
            if len(self.cache) >= self.max_size and key not in self.cache:
                self.cache.popitem(last=False)
                self.stats["evictions"] += 1

            self.cache[key] = {
                "value": value,
                "expires_at": time.time() + ttl,
                "created_at": time.time()
            }

            # Move to end (most recently used)
            self.cache.move_to_end(key)
            self.stats["sets"] += 1

    def invalidate(self, key):
        """Remove specific key from cache."""
        with self.lock:
            if key in self.cache:
                del self.cache[key]

    def clear(self):
        """Clear entire cache."""
        with self.lock:
            self.cache.clear()

    def get_stats(self):
        """
        Get cache statistics.

        Returns:
            dict: Cache performance metrics
        """
        with self.lock:
            total_requests = self.stats["hits"] + self.stats["misses"]
            hit_rate = (self.stats["hits"] / total_requests * 100) if total_requests > 0 else 0

            return {
                **self.stats,
                "size": len(self.cache),
                "max_size": self.max_size,
                "hit_rate": round(hit_rate, 2),
                "total_requests": total_requests
            }

    def cleanup_expired(self):
        """Remove all expired entries (maintenance operation)."""
        with self.lock:
            expired_keys = [
                key for key, entry in self.cache.items()
                if self._is_expired(entry)
            ]
            for key in expired_keys:
                del self.cache[key]
            return len(expired_keys)


# Global cache instance
response_cache = ResponseCache(max_size=500, default_ttl=300)


def get_cache_key(indicator_type, indicator_value, api_name):
    """
    Generate consistent cache key.

    Args:
        indicator_type: "ip", "hash", "url", "domain"
        indicator_value: The actual indicator
        api_name: "abuseipdb", "virustotal", "shodan", "whois"

    Returns:
        str: Cache key
    """
    return f"{api_name}:{indicator_type}:{indicator_value.lower()}"
