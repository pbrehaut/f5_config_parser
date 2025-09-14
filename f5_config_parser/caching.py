import hashlib
import json
import os
from typing import Dict, List, Optional


class DependencyCache:
    """Handles caching of dependency data based on config hash"""

    def __init__(self, config_str: str):
        """Initialise cache with config string for hash generation"""
        self.config_hash = self._calculate_config_hash(config_str)
        self.cache_dir = "cache"
        self._ensure_cache_dir()

    def _ensure_cache_dir(self) -> None:
        """Create cache directory if it doesn't exist"""
        if not os.path.exists(self.cache_dir):
            os.makedirs(self.cache_dir)

    def _calculate_config_hash(self, config_str: str) -> str:
        """Calculate MD5 hash of the config string"""
        return hashlib.md5(config_str.encode('utf-8')).hexdigest()

    def _get_cache_filename(self, cache_type: str) -> str:
        """Generate cache filename based on config hash and cache type"""
        filename = f"dependency_cache_{cache_type}_{self.config_hash}.json"
        return os.path.join(self.cache_dir, filename)

    def load(self, cache_type: str) -> Optional[Dict[str, List[str]]]:
        """Load dependency data from cache file if it exists"""
        try:
            cache_filename = self._get_cache_filename(cache_type)
            with open(cache_filename, 'r') as f:
                dependencies_data = json.load(f)
            print(f"Loaded {cache_type} cache from {cache_filename}")
            return dependencies_data
        except (FileNotFoundError, json.JSONDecodeError, Exception):
            return None

    def save(self, dependencies_data: Dict[str, List[str]], cache_type: str) -> None:
        """Save dependency data to cache file"""
        cache_filename = self._get_cache_filename(cache_type)
        try:
            with open(cache_filename, 'w') as f:
                json.dump(dependencies_data, f, indent=2)
            print(f"Saved {cache_type} cache to {cache_filename}")
        except Exception as e:
            print(f"Warning: Failed to save {cache_type} cache: {e}")