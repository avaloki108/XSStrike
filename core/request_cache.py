"""
Request Caching System for XSStrike.

This module implements intelligent request caching to avoid redundant HTTP
requests, improve scanning performance, and reduce server load while
maintaining scan accuracy and effectiveness.
"""

import hashlib
import json
import time
import pickle
import sqlite3
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Union
from dataclasses import dataclass, asdict
from urllib.parse import urlparse, parse_qs
from threading import Lock

from core.log import setup_logger

logger = setup_logger(__name__)


@dataclass
class CacheEntry:
    """Represents a cached request/response pair."""
    request_hash: str
    url: str
    method: str
    headers: Dict[str, str]
    data: Optional[str]
    response_status: int
    response_headers: Dict[str, str]
    response_content: str
    response_time: float
    cached_at: float
    access_count: int = 0
    last_accessed: Optional[float] = None
    ttl: float = 3600  # 1 hour default TTL


@dataclass
class CacheStats:
    """Statistics about cache performance."""
    total_requests: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    cache_size: int = 0
    hit_rate: float = 0.0
    avg_response_time_cached: float = 0.0
    avg_response_time_fresh: float = 0.0
    bytes_saved: int = 0


class RequestCache:
    """
    Intelligent HTTP request cache for XSStrike.
    
    This cache system:
    - Avoids redundant requests to the same URLs with same parameters
    - Respects cache headers and TTL
    - Handles different request methods appropriately
    - Provides cache statistics and management
    - Thread-safe operations
    - Persistent storage with SQLite
    """

    def __init__(self, cache_dir: str = "data/cache", max_cache_size: int = 10000):
        self.cache_dir = Path(cache_dir)
        self.max_cache_size = max_cache_size
        self.logger = setup_logger(__name__)
        self.lock = Lock()

        # Cache configuration
        self.default_ttl = 3600  # 1 hour
        self.max_ttl = 24 * 3600  # 24 hours
        self.min_ttl = 300  # 5 minutes

        # Statistics
        self.stats = CacheStats()

        # Initialize cache
        self._ensure_cache_directory()
        self._initialize_database()
        self._load_stats()

    def _ensure_cache_directory(self) -> None:
        """Ensure cache directory exists."""
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _initialize_database(self) -> None:
        """Initialize SQLite cache database."""
        db_path = self.cache_dir / "request_cache.db"

        with sqlite3.connect(str(db_path)) as conn:
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("PRAGMA synchronous = NORMAL")

            # Cache entries table
            conn.execute("""
                         CREATE TABLE IF NOT EXISTS cache_entries
                         (
                             request_hash
                             TEXT
                             PRIMARY
                             KEY,
                             url
                             TEXT
                             NOT
                             NULL,
                             method
                             TEXT
                             NOT
                             NULL,
                             headers
                             TEXT,
                             data
                             TEXT,
                             response_status
                             INTEGER,
                             response_headers
                             TEXT,
                             response_content
                             BLOB,
                             response_time
                             REAL,
                             cached_at
                             REAL,
                             access_count
                             INTEGER
                             DEFAULT
                             0,
                             last_accessed
                             REAL,
                             ttl
                             REAL
                         )
            """)

            # Indexes for performance
            conn.execute("CREATE INDEX IF NOT EXISTS idx_url ON cache_entries(url)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_cached_at ON cache_entries(cached_at)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_access_count ON cache_entries(access_count)")

            conn.commit()

    def _load_stats(self) -> None:
        """Load cache statistics from database."""
        db_path = self.cache_dir / "request_cache.db"

        try:
            with sqlite3.connect(str(db_path)) as conn:
                # Get cache size
                cursor = conn.execute("SELECT COUNT(*) FROM cache_entries")
                self.stats.cache_size = cursor.fetchone()[0]

                # Calculate hit rate if we have historical data
                # This would be loaded from a separate stats table in a full implementation

        except sqlite3.Error as e:
            self.logger.error(f"Error loading cache stats: {e}")

    def _generate_request_hash(self, url: str, method: str = "GET",
                               headers: Optional[Dict[str, str]] = None,
                               data: Optional[str] = None) -> str:
        """Generate a unique hash for a request."""
        # Parse URL to normalize it
        parsed_url = urlparse(url)

        # Normalize URL components
        normalized_url = f"{parsed_url.scheme}://{parsed_url.netloc.lower()}{parsed_url.path}"

        # Sort query parameters for consistent hashing
        if parsed_url.query:
            query_params = parse_qs(parsed_url.query)
            sorted_params = sorted(query_params.items())
            normalized_query = "&".join(f"{k}={v[0]}" for k, v in sorted_params)
            normalized_url += f"?{normalized_query}"

        # Create hash input
        hash_input = {
            'url': normalized_url,
            'method': method.upper(),
            'data': data
        }

        # Include relevant headers (excluding time-sensitive ones)
        if headers:
            relevant_headers = {}
            for key, value in headers.items():
                key_lower = key.lower()
                if key_lower not in ['user-agent', 'date', 'timestamp', 'x-requested-with']:
                    relevant_headers[key_lower] = value

            if relevant_headers:
                hash_input['headers'] = relevant_headers

        # Generate hash
        hash_string = json.dumps(hash_input, sort_keys=True)
        return hashlib.sha256(hash_string.encode()).hexdigest()

    def get(self, url: str, method: str = "GET", headers: Optional[Dict[str, str]] = None,
            data: Optional[str] = None) -> Optional[CacheEntry]:
        """
        Get cached response for a request.
        
        Args:
            url: Request URL
            method: HTTP method
            headers: Request headers
            data: Request data (for POST requests)
            
        Returns:
            CacheEntry if found and valid, None otherwise
        """
        with self.lock:
            self.stats.total_requests += 1

            request_hash = self._generate_request_hash(url, method, headers, data)

            db_path = self.cache_dir / "request_cache.db"

            try:
                with sqlite3.connect(str(db_path)) as conn:
                    conn.row_factory = sqlite3.Row

                    cursor = conn.execute("""
                                          SELECT *
                                          FROM cache_entries
                                          WHERE request_hash = ?
                    """, (request_hash,))

                    row = cursor.fetchone()
                    if not row:
                        self.stats.cache_misses += 1
                        return None

                    # Check if entry is still valid (TTL)
                    current_time = time.time()
                    if current_time - row['cached_at'] > row['ttl']:
                        # Entry expired, remove it
                        conn.execute("DELETE FROM cache_entries WHERE request_hash = ?", (request_hash,))
                        conn.commit()
                        self.stats.cache_misses += 1
                        return None

                    # Update access statistics
                    conn.execute("""
                                 UPDATE cache_entries
                                 SET access_count  = access_count + 1,
                                     last_accessed = ?
                                 WHERE request_hash = ?
                    """, (current_time, request_hash))
                    conn.commit()

                    # Create cache entry
                    entry = CacheEntry(
                        request_hash=row['request_hash'],
                        url=row['url'],
                        method=row['method'],
                        headers=json.loads(row['headers'] or '{}'),
                        data=row['data'],
                        response_status=row['response_status'],
                        response_headers=json.loads(row['response_headers'] or '{}'),
                        response_content=row['response_content'].decode('utf-8') if row['response_content'] else '',
                        response_time=row['response_time'],
                        cached_at=row['cached_at'],
                        access_count=row['access_count'] + 1,
                        last_accessed=current_time,
                        ttl=row['ttl']
                    )

                    self.stats.cache_hits += 1
                    self.stats.hit_rate = self.stats.cache_hits / self.stats.total_requests

                    self.logger.debug(f"Cache HIT for {method} {url}")
                    return entry

            except sqlite3.Error as e:
                self.logger.error(f"Error retrieving from cache: {e}")
                self.stats.cache_misses += 1
                return None

    def put(self, url: str, method: str, headers: Optional[Dict[str, str]] = None,
            data: Optional[str] = None, response_status: int = 200,
            response_headers: Optional[Dict[str, str]] = None,
            response_content: str = "", response_time: float = 0.0,
            custom_ttl: Optional[float] = None) -> bool:
        """
        Store a response in the cache.
        
        Args:
            url: Request URL
            method: HTTP method
            headers: Request headers
            data: Request data
            response_status: HTTP response status
            response_headers: Response headers
            response_content: Response content
            response_time: Response time in seconds
            custom_ttl: Custom TTL override
            
        Returns:
            bool: True if stored successfully
        """
        with self.lock:
            # Don't cache certain response types
            if not self._should_cache_response(response_status, response_headers or {}):
                return False

            request_hash = self._generate_request_hash(url, method, headers, data)

            # Determine TTL
            ttl = custom_ttl or self._calculate_ttl(response_headers or {})

            current_time = time.time()

            entry = CacheEntry(
                request_hash=request_hash,
                url=url,
                method=method,
                headers=headers or {},
                data=data,
                response_status=response_status,
                response_headers=response_headers or {},
                response_content=response_content,
                response_time=response_time,
                cached_at=current_time,
                ttl=ttl
            )

            db_path = self.cache_dir / "request_cache.db"

            try:
                with sqlite3.connect(str(db_path)) as conn:
                    # Check cache size and clean if necessary
                    if self.stats.cache_size >= self.max_cache_size:
                        self._cleanup_cache(conn)

                    # Store the entry
                    conn.execute("""
                        INSERT OR REPLACE INTO cache_entries
                        (request_hash, url, method, headers, data, response_status,
                         response_headers, response_content, response_time, cached_at, ttl)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        entry.request_hash, entry.url, entry.method,
                        json.dumps(entry.headers), entry.data, entry.response_status,
                        json.dumps(entry.response_headers), entry.response_content.encode('utf-8'),
                        entry.response_time, entry.cached_at, entry.ttl
                    ))

                    conn.commit()
                    self.stats.cache_size += 1

                    self.logger.debug(f"Cache STORE for {method} {url} (TTL: {ttl}s)")
                    return True

            except sqlite3.Error as e:
                self.logger.error(f"Error storing in cache: {e}")
                return False

    def _should_cache_response(self, status: int, headers: Dict[str, str]) -> bool:
        """Determine if a response should be cached."""
        # Don't cache error responses
        if status >= 400:
            return False

        # Check Cache-Control headers
        cache_control = headers.get('cache-control', '').lower()
        if 'no-cache' in cache_control or 'no-store' in cache_control:
            return False

        # Don't cache responses with Set-Cookie (they might be session-specific)
        if 'set-cookie' in headers:
            return False

        # Don't cache very large responses
        content_length = headers.get('content-length')
        if content_length and int(content_length) > 1024 * 1024:  # 1MB
            return False

        return True

    def _calculate_ttl(self, headers: Dict[str, str]) -> float:
        """Calculate TTL based on response headers."""
        # Check Cache-Control max-age
        cache_control = headers.get('cache-control', '')
        if 'max-age=' in cache_control:
            try:
                max_age = int(cache_control.split('max-age=')[1].split(',')[0])
                return max(self.min_ttl, min(max_age, self.max_ttl))
            except (ValueError, IndexError):
                pass

        # Check Expires header
        expires = headers.get('expires')
        if expires:
            try:
                from email.utils import parsedate_to_datetime
                expires_dt = parsedate_to_datetime(expires)
                ttl = (expires_dt.timestamp() - time.time())
                if ttl > 0:
                    return max(self.min_ttl, min(ttl, self.max_ttl))
            except Exception:
                pass

        # Default TTL based on content type
        content_type = headers.get('content-type', '').lower()
        if 'text/html' in content_type:
            return 1800  # 30 minutes for HTML
        elif any(t in content_type for t in ['javascript', 'css', 'image']):
            return 3600  # 1 hour for static resources

        return self.default_ttl

    def _cleanup_cache(self, conn: sqlite3.Connection) -> None:
        """Clean up old cache entries to make space."""
        # Remove expired entries first
        current_time = time.time()
        conn.execute("""
                     DELETE
                     FROM cache_entries
                     WHERE (cached_at + ttl) < ?
        """, (current_time,))

        # If still too large, remove least recently used entries
        remaining_count = conn.execute("SELECT COUNT(*) FROM cache_entries").fetchone()[0]

        if remaining_count >= self.max_cache_size:
            # Remove oldest entries (by last_accessed, then by cached_at)
            entries_to_remove = remaining_count - (self.max_cache_size * 0.8)  # Remove 20% extra

            conn.execute("""
                         DELETE
                         FROM cache_entries
                         WHERE request_hash IN (SELECT request_hash
                                                FROM cache_entries
                                                ORDER BY COALESCE(last_accessed, cached_at) ASC
                             LIMIT ?
                             )
            """, (int(entries_to_remove),))

        conn.commit()

        # Update stats
        self.stats.cache_size = conn.execute("SELECT COUNT(*) FROM cache_entries").fetchone()[0]

    def clear(self) -> None:
        """Clear all cache entries."""
        with self.lock:
            db_path = self.cache_dir / "request_cache.db"

            try:
                with sqlite3.connect(str(db_path)) as conn:
                    conn.execute("DELETE FROM cache_entries")
                    conn.commit()

                self.stats = CacheStats()
                self.logger.info("Cache cleared successfully")

            except sqlite3.Error as e:
                self.logger.error(f"Error clearing cache: {e}")

    def get_stats(self) -> CacheStats:
        """Get current cache statistics."""
        with self.lock:
            # Update cache size
            db_path = self.cache_dir / "request_cache.db"

            try:
                with sqlite3.connect(str(db_path)) as conn:
                    self.stats.cache_size = conn.execute("SELECT COUNT(*) FROM cache_entries").fetchone()[0]
            except sqlite3.Error:
                pass

            # Calculate hit rate
            if self.stats.total_requests > 0:
                self.stats.hit_rate = self.stats.cache_hits / self.stats.total_requests

            return self.stats

    def invalidate_url(self, url: str) -> int:
        """
        Invalidate all cache entries for a specific URL.
        
        Args:
            url: URL to invalidate
            
        Returns:
            int: Number of entries invalidated
        """
        with self.lock:
            db_path = self.cache_dir / "request_cache.db"

            try:
                with sqlite3.connect(str(db_path)) as conn:
                    cursor = conn.execute("DELETE FROM cache_entries WHERE url = ?", (url,))
                    invalidated_count = cursor.rowcount
                    conn.commit()

                    self.stats.cache_size -= invalidated_count
                    self.logger.info(f"Invalidated {invalidated_count} cache entries for {url}")

                    return invalidated_count

            except sqlite3.Error as e:
                self.logger.error(f"Error invalidating cache for {url}: {e}")
                return 0

    def invalidate_domain(self, domain: str) -> int:
        """
        Invalidate all cache entries for a specific domain.
        
        Args:
            domain: Domain to invalidate
            
        Returns:
            int: Number of entries invalidated
        """
        with self.lock:
            db_path = self.cache_dir / "request_cache.db"

            try:
                with sqlite3.connect(str(db_path)) as conn:
                    cursor = conn.execute(
                        "DELETE FROM cache_entries WHERE url LIKE ?",
                        (f"%{domain}%",)
                    )
                    invalidated_count = cursor.rowcount
                    conn.commit()

                    self.stats.cache_size -= invalidated_count
                    self.logger.info(f"Invalidated {invalidated_count} cache entries for domain {domain}")

                    return invalidated_count

            except sqlite3.Error as e:
                self.logger.error(f"Error invalidating cache for domain {domain}: {e}")
                return 0


# Global request cache instance
request_cache = RequestCache()
