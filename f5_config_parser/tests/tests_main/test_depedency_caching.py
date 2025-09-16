import pytest
import json
import os
import tempfile
import shutil
from pathlib import Path
from unittest.mock import patch, mock_open

from f5_config_parser.caching import DependencyCache


class TestDependencyCache:

    @pytest.fixture
    def temp_cache_dir(self):
        """Create a temporary directory for cache testing"""
        temp_dir = tempfile.mkdtemp()
        yield temp_dir
        shutil.rmtree(temp_dir)

    @pytest.fixture
    def sample_config_str(self):
        """Sample config string for testing"""
        return """
        ltm pool test_pool {
            members {
                192.168.1.10:80
                192.168.1.11:80
            }
        }
        ltm virtual test_vs {
            pool test_pool
            destination 10.0.0.100:80
        }
        """

    @pytest.fixture
    def sample_dependencies(self):
        """Sample dependency data for testing"""
        return {
            "/Common/test_vs": ["/Common/test_pool"],
            "/Common/test_pool": [],
            "/Common/another_object": ["/Common/dependency1", "/Common/dependency2"]
        }

    @pytest.fixture
    def cache_with_temp_dir(self, sample_config_str, temp_cache_dir):
        """Cache instance with custom cache directory"""
        with patch.object(DependencyCache, '_ensure_cache_dir'):
            cache = DependencyCache(sample_config_str)
            cache.cache_dir = temp_cache_dir
            return cache

    def test_init_creates_cache_hash(self, sample_config_str):
        """Test that initialisation creates a config hash"""
        cache = DependencyCache(sample_config_str)
        assert cache.config_hash is not None
        assert len(cache.config_hash) == 32  # MD5 hash length
        assert isinstance(cache.config_hash, str)

    def test_init_creates_cache_directory(self, sample_config_str, temp_cache_dir):
        """Test that initialisation creates cache directory"""
        with patch('os.makedirs') as mock_makedirs:
            with patch('os.path.exists', return_value=False):
                cache = DependencyCache(sample_config_str)
                mock_makedirs.assert_called_once_with("cache")

    def test_init_skips_directory_creation_if_exists(self, sample_config_str):
        """Test that directory creation is skipped if cache dir already exists"""
        with patch('os.makedirs') as mock_makedirs:
            with patch('os.path.exists', return_value=True):
                cache = DependencyCache(sample_config_str)
                mock_makedirs.assert_not_called()

    def test_hash_consistency(self, sample_config_str):
        """Test that the same config string always produces the same hash"""
        cache1 = DependencyCache(sample_config_str)
        cache2 = DependencyCache(sample_config_str)
        assert cache1.config_hash == cache2.config_hash

    def test_hash_uniqueness(self):
        """Test that different config strings produce different hashes"""
        config1 = "ltm pool pool1 { }"
        config2 = "ltm pool pool2 { }"

        cache1 = DependencyCache(config1)
        cache2 = DependencyCache(config2)

        assert cache1.config_hash != cache2.config_hash

    def test_get_cache_filename(self, cache_with_temp_dir, temp_cache_dir):
        """Test cache filename generation"""
        filename = cache_with_temp_dir._get_cache_filename("dependencies")

        expected_filename = f"cache_dependencies_{cache_with_temp_dir.config_hash}.json"
        expected_path = os.path.join(temp_cache_dir, expected_filename)

        assert filename == expected_path

    def test_save_and_load_cache(self, cache_with_temp_dir, sample_dependencies):
        """Test saving and loading cache data"""
        cache_type = "standard"

        # Save data
        cache_with_temp_dir.save(sample_dependencies, cache_type)

        # Verify file was created
        cache_filename = cache_with_temp_dir._get_cache_filename(cache_type)
        assert os.path.exists(cache_filename)

        # Load data
        loaded_data = cache_with_temp_dir.load(cache_type)

        assert loaded_data == sample_dependencies

    def test_load_nonexistent_cache_returns_none(self, cache_with_temp_dir):
        """Test that loading non-existent cache returns None"""
        result = cache_with_temp_dir.load("nonexistent")
        assert result is None

    def test_load_corrupted_cache_returns_none(self, cache_with_temp_dir):
        """Test that loading corrupted cache file returns None"""
        cache_type = "corrupted"
        cache_filename = cache_with_temp_dir._get_cache_filename(cache_type)

        # Create a corrupted JSON file
        with open(cache_filename, 'w') as f:
            f.write("{ invalid json content")

        result = cache_with_temp_dir.load(cache_type)
        assert result is None

    def test_save_handles_write_errors_gracefully(self, cache_with_temp_dir, sample_dependencies):
        """Test that save method handles write errors gracefully"""
        with patch('builtins.open', mock_open()) as mock_file:
            mock_file.side_effect = IOError("Permission denied")

            # Should not raise exception
            cache_with_temp_dir.save(sample_dependencies, "test")

    def test_different_cache_types_separate_files(self, cache_with_temp_dir, sample_dependencies):
        """Test that different cache types create separate files"""
        dependencies1 = {"obj1": ["dep1"]}
        dependencies2 = {"obj2": ["dep2"]}

        cache_with_temp_dir.save(dependencies1, "standard")
        cache_with_temp_dir.save(dependencies2, "irule")

        loaded_standard = cache_with_temp_dir.load("standard")
        loaded_irule = cache_with_temp_dir.load("irule")

        assert loaded_standard == dependencies1
        assert loaded_irule == dependencies2
        assert loaded_standard != loaded_irule

    def test_cache_with_real_config_data(self, f5_config):
        """Test cache functionality with real F5 config data"""
        # Create cache from real config
        cache = DependencyCache(f5_config.config_str)

        # Create some mock dependency data
        dependencies = {}
        for stanza in f5_config.stanzas[:5]:  # Use first 5 stanzas
            dependencies[stanza.full_path] = [f"/Common/dep_{i}" for i in range(2)]

        # Test save and load
        cache.save(dependencies, "real_config_test")
        loaded = cache.load("real_config_test")

        assert loaded == dependencies

    def test_cache_hash_changes_with_config_content(self):
        """Test that hash changes when config content changes"""
        base_config = "ltm pool test { }"
        modified_config = base_config + "\nltm pool test2 { }"

        cache1 = DependencyCache(base_config)
        cache2 = DependencyCache(modified_config)

        assert cache1.config_hash != cache2.config_hash

    def test_empty_config_string(self):
        """Test cache with empty config string"""
        cache = DependencyCache("")
        assert cache.config_hash is not None
        assert len(cache.config_hash) == 32

    def test_unicode_config_string(self):
        """Test cache with unicode characters in config"""
        unicode_config = "ltm pool tëst { # Special characters: 中文 ñ ü }"
        cache = DependencyCache(unicode_config)

        dependencies = {"/Common/test": ["dep1"]}
        cache.save(dependencies, "unicode_test")
        loaded = cache.load("unicode_test")

        assert loaded == dependencies

    @pytest.fixture
    def f5_config(self):
        """Full F5 configuration for realistic testing"""
        test_dir = Path(__file__).parent
        with open(test_dir / '../data/f5_scf_config.txt') as f:
            from f5_config_parser.collection import StanzaCollection  # Adjust import as needed
            return StanzaCollection.from_config(f.read())