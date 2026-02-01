"""
Cache Manager for OWASP Cheat Sheet Viewer
==========================================

Handles disk-based caching with configurable expiration times.
"""

import hashlib
import json
import logging
import shutil
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Optional

from .config_manager import ConfigManager


logger = logging.getLogger(__name__)


class CacheManager:
    """
    Manages disk-based caching for cheat sheet data.
    
    Features:
    - Configurable expiration times
    - Content hashing for change detection
    - Automatic cleanup of expired entries
    - Size management
    """
    
    def __init__(self, config: Optional[ConfigManager] = None) -> None:
        """
        Initialize the cache manager.
        
        Args:
            config: Configuration manager instance
        """
        self._config = config or ConfigManager()
        self._cache_dir = self._config.cache_directory
        self._enabled = self._config.get("cache.enabled", True)
        self._default_expiry_days = self._config.cache_expiry_days
        self._index_expiry_days = self._config.index_expiry_days
        self._max_size_mb = self._config.get("cache.max_size_mb", 500)
        
        # Ensure cache directory exists
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        
        # Metadata file for tracking cache state
        self._metadata_file = self._cache_dir / "_metadata.json"
        self._metadata = self._load_metadata()
    
    def _load_metadata(self) -> dict[str, Any]:
        """Load cache metadata from disk."""
        if self._metadata_file.exists():
            try:
                with open(self._metadata_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError) as e:
                logger.warning(f"Failed to load cache metadata: {e}")
        return {"entries": {}, "total_size_bytes": 0}
    
    def _save_metadata(self) -> None:
        """Save cache metadata to disk."""
        try:
            with open(self._metadata_file, "w", encoding="utf-8") as f:
                json.dump(self._metadata, f, indent=2, default=str)
        except IOError as e:
            logger.error(f"Failed to save cache metadata: {e}")
    
    def _generate_key(self, identifier: str) -> str:
        """
        Generate a safe cache key from an identifier.
        
        Args:
            identifier: Original identifier (e.g., URL or cheat sheet ID)
            
        Returns:
            Safe filename-compatible cache key
        """
        # Create a hash for the key
        hash_obj = hashlib.sha256(identifier.encode("utf-8"))
        return hash_obj.hexdigest()[:32]
    
    def _get_cache_path(self, key: str) -> Path:
        """Get the file path for a cache key."""
        return self._cache_dir / f"{key}.json"
    
    def _compute_content_hash(self, data: Any) -> str:
        """Compute a hash of the content for change detection."""
        content_str = json.dumps(data, sort_keys=True, default=str)
        return hashlib.sha256(content_str.encode("utf-8")).hexdigest()[:16]
    
    def get(
        self,
        identifier: str,
        ignore_expiry: bool = False
    ) -> Optional[dict[str, Any]]:
        """
        Retrieve data from cache.
        
        Args:
            identifier: Cache identifier (URL or ID)
            ignore_expiry: If True, return data even if expired
            
        Returns:
            Cached data or None if not found/expired
        """
        if not self._enabled:
            return None
        
        key = self._generate_key(identifier)
        cache_path = self._get_cache_path(key)
        
        if not cache_path.exists():
            logger.debug(f"Cache miss: {identifier}")
            return None
        
        try:
            with open(cache_path, "r", encoding="utf-8") as f:
                entry = json.load(f)
            
            # Check expiration
            expires_at = datetime.fromisoformat(entry.get("expires_at", ""))
            if not ignore_expiry and datetime.now() > expires_at:
                logger.debug(f"Cache expired: {identifier}")
                self.delete(identifier)
                return None
            
            logger.debug(f"Cache hit: {identifier}")
            return entry.get("data")
            
        except (json.JSONDecodeError, IOError, ValueError) as e:
            logger.warning(f"Failed to read cache entry: {e}")
            return None
    
    def set(
        self,
        identifier: str,
        data: Any,
        expiry_days: Optional[int] = None,
        is_index: bool = False
    ) -> bool:
        """
        Store data in cache.
        
        Args:
            identifier: Cache identifier (URL or ID)
            data: Data to cache
            expiry_days: Custom expiry time in days
            is_index: If True, use shorter index expiry time
            
        Returns:
            True if successful, False otherwise
        """
        if not self._enabled:
            return False
        
        # Determine expiry time
        if expiry_days is None:
            expiry_days = self._index_expiry_days if is_index else self._default_expiry_days
        
        key = self._generate_key(identifier)
        cache_path = self._get_cache_path(key)
        
        entry = {
            "identifier": identifier,
            "key": key,
            "data": data,
            "created_at": datetime.now().isoformat(),
            "expires_at": (datetime.now() + timedelta(days=expiry_days)).isoformat(),
            "content_hash": self._compute_content_hash(data),
        }
        
        try:
            # Write to cache file
            with open(cache_path, "w", encoding="utf-8") as f:
                json.dump(entry, f, indent=2, default=str)
            
            # Update metadata
            file_size = cache_path.stat().st_size
            self._metadata["entries"][key] = {
                "identifier": identifier,
                "size_bytes": file_size,
                "expires_at": entry["expires_at"],
            }
            self._metadata["total_size_bytes"] = sum(
                e.get("size_bytes", 0) for e in self._metadata["entries"].values()
            )
            self._save_metadata()
            
            logger.debug(f"Cached: {identifier} (expires in {expiry_days} days)")
            
            # Check if cleanup is needed
            self._check_size_limit()
            
            return True
            
        except IOError as e:
            logger.error(f"Failed to write cache entry: {e}")
            return False
    
    def delete(self, identifier: str) -> bool:
        """
        Delete a cache entry.
        
        Args:
            identifier: Cache identifier
            
        Returns:
            True if deleted, False if not found
        """
        key = self._generate_key(identifier)
        cache_path = self._get_cache_path(key)
        
        if cache_path.exists():
            try:
                cache_path.unlink()
                if key in self._metadata["entries"]:
                    del self._metadata["entries"][key]
                    self._save_metadata()
                logger.debug(f"Deleted cache entry: {identifier}")
                return True
            except IOError as e:
                logger.error(f"Failed to delete cache entry: {e}")
        return False
    
    def has_valid_cache(self, identifier: str) -> bool:
        """
        Check if a valid (non-expired) cache entry exists.
        
        Args:
            identifier: Cache identifier
            
        Returns:
            True if valid cache exists
        """
        return self.get(identifier) is not None
    
    def get_expiry_time(self, identifier: str) -> Optional[datetime]:
        """
        Get the expiration time for a cache entry.
        
        Args:
            identifier: Cache identifier
            
        Returns:
            Expiration datetime or None
        """
        key = self._generate_key(identifier)
        entry_meta = self._metadata["entries"].get(key, {})
        expires_at_str = entry_meta.get("expires_at")
        
        if expires_at_str:
            try:
                return datetime.fromisoformat(expires_at_str)
            except ValueError:
                pass
        return None
    
    def cleanup_expired(self) -> int:
        """
        Remove all expired cache entries.
        
        Returns:
            Number of entries removed
        """
        removed_count = 0
        current_time = datetime.now()
        
        for key, entry_meta in list(self._metadata["entries"].items()):
            try:
                expires_at = datetime.fromisoformat(entry_meta.get("expires_at", ""))
                if current_time > expires_at:
                    cache_path = self._get_cache_path(key)
                    if cache_path.exists():
                        cache_path.unlink()
                    del self._metadata["entries"][key]
                    removed_count += 1
            except (ValueError, IOError):
                continue
        
        if removed_count > 0:
            self._save_metadata()
            logger.info(f"Cleaned up {removed_count} expired cache entries")
        
        return removed_count
    
    def _check_size_limit(self) -> None:
        """Check and enforce cache size limit."""
        max_bytes = self._max_size_mb * 1024 * 1024
        
        if self._metadata["total_size_bytes"] <= max_bytes:
            return
        
        # Sort entries by expiration (oldest first)
        sorted_entries = sorted(
            self._metadata["entries"].items(),
            key=lambda x: x[1].get("expires_at", "")
        )
        
        # Remove oldest entries until under limit
        for key, _ in sorted_entries:
            if self._metadata["total_size_bytes"] <= max_bytes * 0.8:  # 80% threshold
                break
            
            cache_path = self._get_cache_path(key)
            if cache_path.exists():
                try:
                    cache_path.unlink()
                    size = self._metadata["entries"][key].get("size_bytes", 0)
                    del self._metadata["entries"][key]
                    self._metadata["total_size_bytes"] -= size
                except IOError:
                    continue
        
        self._save_metadata()
    
    def clear_all(self) -> None:
        """Clear all cache entries."""
        try:
            # Remove all JSON files in cache directory
            for cache_file in self._cache_dir.glob("*.json"):
                if cache_file.name != "_metadata.json":
                    cache_file.unlink()
            
            self._metadata = {"entries": {}, "total_size_bytes": 0}
            self._save_metadata()
            logger.info("Cache cleared")
            
        except IOError as e:
            logger.error(f"Failed to clear cache: {e}")
    
    def get_stats(self) -> dict[str, Any]:
        """
        Get cache statistics.
        
        Returns:
            Dictionary with cache stats
        """
        return {
            "enabled": self._enabled,
            "directory": str(self._cache_dir),
            "entry_count": len(self._metadata["entries"]),
            "total_size_mb": round(self._metadata["total_size_bytes"] / (1024 * 1024), 2),
            "max_size_mb": self._max_size_mb,
            "default_expiry_days": self._default_expiry_days,
            "index_expiry_days": self._index_expiry_days,
        }
