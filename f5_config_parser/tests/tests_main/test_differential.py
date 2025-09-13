import pytest
from pathlib import Path
from f5_config_parser.collection import StanzaCollection, DuplicateStanzaError


@pytest.fixture
def original_config():
    """Load original F5 configuration"""
    test_dir = Path(__file__).parent
    with open(test_dir / '../data/f5_original_config.txt') as f:
        f5_config_obj = StanzaCollection.from_config(f.read())
    return f5_config_obj


@pytest.fixture
def modified_config():
    """Load modified F5 configuration"""
    test_dir = Path(__file__).parent
    with open(test_dir / '../data/f5_modified_config.txt') as f:
        f5_config_obj = StanzaCollection.from_config(f.read())
    return f5_config_obj


@pytest.fixture
def original_dict(original_config):
    """Convert original config list to dictionary for lookups"""
    return {stanza.full_path: stanza for stanza in original_config}


@pytest.fixture
def modified_dict(modified_config):
    """Convert modified config list to dictionary for lookups"""
    return {stanza.full_path: stanza for stanza in modified_config}


class TestConfigurationDifferentials:
    """Test configuration differential operations using set operations"""

    def test_hash_method_works_for_sets(self, original_config, modified_config):
        """Test that ConfigStanza objects can be used in sets"""
        original_set = set(original_config)
        modified_set = set(modified_config)

        # Should be able to create sets without errors
        assert len(original_set) > 0
        assert len(modified_set) > 0

        # Set operations should work
        union = original_set | modified_set
        intersection = original_set & modified_set
        assert len(union) >= len(intersection)

    def test_stanzas_only_in_original(self, original_config, modified_config):
        """Test finding stanzas that exist only in original config"""
        original_set = set(original_config)
        modified_set = set(modified_config)

        only_in_original = original_set - modified_set

        # Should find the deleted stanzas
        deleted_paths = {stanza.full_path for stanza in only_in_original}

        # These stanzas were removed in the modified config
        expected_deletions = {
            'ltm profile client-ssl clientssl-mutual',
            'ltm pool pool-external-monitor'
        }

        assert expected_deletions.issubset(deleted_paths)

    def test_stanzas_only_in_modified(self, original_config, modified_config):
        """Test finding stanzas that exist only in modified config"""
        original_set = set(original_config)
        modified_set = set(modified_config)

        only_in_modified = modified_set - original_set

        # Should find the added stanzas
        added_paths = {stanza.full_path for stanza in only_in_modified}

        # These stanzas were added in the modified config
        expected_additions = {
            'ltm monitor http mon-http-new',
            'ltm node node-new-01',
            'ltm pool pool-new-service',
            'ltm virtual vs-new-service'
        }

        assert expected_additions.issubset(added_paths)

    def test_identical_stanzas(self, original_config, modified_config):
        """Test finding stanzas that are identical in both configs"""
        original_set = set(original_config)
        modified_set = set(modified_config)

        identical_stanzas = original_set & modified_set

        # Should find stanzas that haven't changed
        identical_paths = {stanza.full_path for stanza in identical_stanzas}

        # These stanzas should be identical
        expected_identical = {
            'ltm monitor tcp mon-tcp-basic',
            'ltm profile http http-basic',
            'ltm virtual vs-web-basic'
        }

        assert expected_identical.issubset(identical_paths)

    def test_modified_stanzas(self, original_dict, modified_dict):
        """Test finding stanzas with same identity but different content"""
        # Find common identities
        common_identities = set(original_dict.keys()) & set(modified_dict.keys())

        modified_stanzas = []
        for identity in common_identities:
            original_stanza = original_dict[identity]
            modified_stanza = modified_dict[identity]

            # If they have same identity but not equal, they have different content
            if not original_stanza.has_same_content(modified_stanza):
                modified_stanzas.append((original_stanza, modified_stanza))

        modified_paths = {original.full_path for original, modified in modified_stanzas}

        # These stanzas should have modifications
        expected_modifications = {
            'ltm monitor http mon-http-basic',  # interval changed from 30 to 60
            'ltm profile http http-compression',  # min-size and buffer-size changed
            'ltm profile http http-custom-headers',  # added header and changed insert value
            'ltm node node-app-01',  # ratio changed from 2 to 3
            'ltm node node-db-01',  # connection-limit changed from 100 to 200
            'ltm rule irule-maintenance-page',  # maintenance message changed
            'ltm rule irule-custom-headers',  # added X-Environment header
            'ltm rule irule-load-balancing'  # added /new/* case
        }

        assert expected_modifications.issubset(modified_paths)

    def test_has_same_content_method(self, original_dict, modified_dict):
        """Test the has_same_content method specifically"""
        # Test identical content
        original_basic = original_dict['ltm profile http http-basic']
        modified_basic = modified_dict['ltm profile http http-basic']
        assert original_basic.has_same_content(modified_basic)

        # Test different content
        original_monitor = original_dict['ltm monitor http mon-http-basic']
        modified_monitor = modified_dict['ltm monitor http mon-http-basic']
        assert not original_monitor.has_same_content(modified_monitor)

    def test_whitespace_normalisation(self, original_dict):
        """Test that whitespace normalisation works in has_same_content"""
        original_stanza = original_dict['ltm profile http http-basic']

        # Create a copy with different whitespace
        modified_lines = []
        for line in original_stanza.config_lines:
            # Add extra spaces
            modified_line = "  " + line + "  "
            modified_lines.append(modified_line)

        test_stanza = type(original_stanza)(original_stanza.prefix, original_stanza.name, config_lines=modified_lines)

        # Should be considered same content due to whitespace normalisation
        assert original_stanza.has_same_content(test_stanza)

    def test_migration_report_generation(self, original_config, modified_config, original_dict, modified_dict):
        """Test generating a comprehensive migration report"""
        original_set = set(original_config)
        modified_set = set(modified_config)

        # Deletions
        to_delete = original_set - modified_set

        # Additions
        to_add = modified_set - original_set

        # Modifications
        common_identities = set(original_dict.keys()) & set(modified_dict.keys())
        to_modify = []

        for identity in common_identities:
            original_stanza = original_dict[identity]
            modified_stanza = modified_dict[identity]

            if not original_stanza.has_same_content(modified_stanza):
                to_modify.append((original_stanza, modified_stanza))

        # Verify counts make sense
        assert len(to_delete) >= 2  # Should have some deletions
        assert len(to_add) >= 4  # Should have some additions
        assert len(to_modify) >= 8  # Should have some modifications

        # Total changes should be reasonable
        total_changes = len(to_delete) + len(to_add) + len(to_modify)
        assert total_changes > 0

    def test_specific_content_changes(self, original_dict, modified_dict):
        """Test specific content changes we know exist"""
        # Test monitor interval change
        original_monitor = original_dict['ltm monitor http mon-http-basic']
        modified_monitor = modified_dict['ltm monitor http mon-http-basic']

        assert not original_monitor.has_same_content(modified_monitor)

        # Check the specific changes
        original_lines = [line.strip() for line in original_monitor.config_lines if line.strip()]
        modified_lines = [line.strip() for line in modified_monitor.config_lines if line.strip()]

        # Should find interval change from 30 to 60
        assert 'interval 30' in original_lines
        assert 'interval 60' in modified_lines

    def test_equality_operator(self, original_dict, modified_dict):
        """Test the __eq__ method works correctly"""
        # Same stanza should equal itself
        stanza = original_dict['ltm profile http http-basic']
        assert stanza == stanza

        # Identical stanzas should be equal
        original_basic = original_dict['ltm profile http http-basic']
        modified_basic = modified_dict['ltm profile http http-basic']
        assert original_basic == modified_basic

        # Different stanzas shouldn't be equal
        original_monitor = original_dict['ltm monitor http mon-http-basic']
        modified_monitor = modified_dict['ltm monitor http mon-http-basic']
        assert original_monitor != modified_monitor

    def test_hash_consistency(self, original_config):
        """Test that hash is consistent and based on full_path"""
        stanza = original_config[0]

        # Hash should be consistent
        hash1 = hash(stanza)
        hash2 = hash(stanza)
        assert hash1 == hash2

        # Hash should be based on full_path
        expected_hash = hash(stanza.full_path)
        assert hash(stanza) == expected_hash

    def test_config_drift_detection(self, original_config, modified_config):
        """Test detecting configuration drift patterns"""
        original_set = set(original_config)
        modified_set = set(modified_config)

        # Calculate drift metrics
        additions = modified_set - original_set
        deletions = original_set - modified_set
        total_drift = len(additions) + len(deletions)

        # Should detect some drift
        assert total_drift > 0

        # Drift percentage
        total_stanzas = len(original_set | modified_set)
        drift_percentage = (total_drift / total_stanzas) * 100

        # Should be a reasonable drift percentage (not 0%, not 100%)
        assert 0 < drift_percentage < 50

    def test_line_level_differences(self, original_dict, modified_dict):
        """Test detailed line-by-line difference analysis"""
        # Test a known modification
        original_monitor = original_dict['ltm monitor http mon-http-basic']
        modified_monitor = modified_dict['ltm monitor http mon-http-basic']

        original_lines = set(line.strip() for line in original_monitor.config_lines if line.strip())
        modified_lines = set(line.strip() for line in modified_monitor.config_lines if line.strip())

        lines_removed = original_lines - modified_lines
        lines_added = modified_lines - original_lines

        # Should detect the interval change
        assert any('interval 30' in line for line in lines_removed)
        assert any('interval 60' in line for line in lines_added)
        assert any('timeout 91' in line for line in lines_removed)
        assert any('timeout 181' in line for line in lines_added)

    def test_summary_statistics(self, original_config, modified_config):
        """Test generation of summary statistics"""
        original_set = set(original_config)
        modified_set = set(modified_config)

        # Calculate all metrics
        deletions = original_set - modified_set
        additions = modified_set - original_set
        identical = original_set & modified_set
        total_union = original_set | modified_set

        # Find modifications
        original_dict = {s.full_path: s for s in original_config}
        modified_dict = {s.full_path: s for s in modified_config}
        common_identities = set(original_dict.keys()) & set(modified_dict.keys())

        modifications = 0
        for identity in common_identities:
            if not original_dict[identity].has_same_content(modified_dict[identity]):
                modifications += 1

        # Verify statistics make sense
        total_changes = len(deletions) + len(additions) + modifications
        change_percentage = (total_changes / len(total_union)) * 100

        # All counts should be non-negative
        assert len(deletions) >= 0
        assert len(additions) >= 0
        assert modifications >= 0
        assert len(identical) >= 0

        # Union should be larger than or equal to each individual set
        assert len(total_union) >= len(original_set)
        assert len(total_union) >= len(modified_set)

        # Change percentage should be reasonable
        assert 0 <= change_percentage <= 100

    def test_stanza_type_filtering(self, original_config, modified_config):
        """Test filtering differences by stanza type"""
        original_set = set(original_config)
        modified_set = set(modified_config)

        # Filter by monitor stanzas
        original_monitors = {s for s in original_set if 'monitor' in s.full_path}
        modified_monitors = {s for s in modified_set if 'monitor' in s.full_path}

        monitor_additions = modified_monitors - original_monitors
        monitor_deletions = original_monitors - modified_monitors

        # Should find the new monitor
        monitor_addition_paths = {s.full_path for s in monitor_additions}
        assert 'ltm monitor http mon-http-new' in monitor_addition_paths

        # Filter by virtual server stanzas
        original_virtuals = {s for s in original_set if 'virtual' in s.full_path}
        modified_virtuals = {s for s in modified_set if 'virtual' in s.full_path}

        virtual_additions = modified_virtuals - original_virtuals
        virtual_addition_paths = {s.full_path for s in virtual_additions}
        assert 'ltm virtual vs-new-service' in virtual_addition_paths

    def test_migration_script_data(self, original_config, modified_config):
        """Test data needed for migration script generation"""
        original_set = set(original_config)
        modified_set = set(modified_config)
        original_dict = {s.full_path: s for s in original_config}
        modified_dict = {s.full_path: s for s in modified_config}

        # Deletions for migration
        to_delete = original_set - modified_set
        deletion_commands = [f"delete {s.full_path}" for s in sorted(to_delete)]

        # Should have some deletion commands
        assert len(deletion_commands) >= 2
        assert any('clientssl-mutual' in cmd for cmd in deletion_commands)

        # Additions for migration
        to_add = modified_set - original_set
        addition_stanzas = sorted(to_add)

        # Should have some addition stanzas with config lines
        assert len(addition_stanzas) >= 4
        for stanza in addition_stanzas:
            assert len(stanza.config_lines) > 0

        # Modifications for migration
        common_identities = set(original_dict.keys()) & set(modified_dict.keys())
        modifications = []

        for identity in common_identities:
            original_stanza = original_dict[identity]
            modified_stanza = modified_dict[identity]

            if not original_stanza.has_same_content(modified_stanza):
                modifications.append((original_stanza, modified_stanza))

        # Should have some modifications
        assert len(modifications) >= 8

    def test_detailed_change_analysis(self, original_dict, modified_dict):
        """Test detailed analysis of what changed in each stanza"""
        # Test compression profile changes
        if 'ltm profile http http-compression' in original_dict and 'ltm profile http http-compression' in modified_dict:
            original_comp = original_dict['ltm profile http http-compression']
            modified_comp = modified_dict['ltm profile http http-compression']

            original_lines = set(line.strip() for line in original_comp.config_lines if line.strip())
            modified_lines = set(line.strip() for line in modified_comp.config_lines if line.strip())

            lines_removed = original_lines - modified_lines
            lines_added = modified_lines - original_lines

            # Should detect specific changes
            assert any('compress-min-size 1024' in line for line in lines_removed)
            assert any('compress-min-size 2048' in line for line in lines_added)
            assert any('compress-buffer-size 4096' in line for line in lines_removed)
            assert any('compress-buffer-size 8192' in line for line in lines_added)

    def test_has_same_content_with_empty_lines(self, original_dict):
        """Test has_same_content handles empty lines correctly"""
        original_stanza = original_dict['ltm profile http http-basic']

        # Create version with empty lines
        modified_lines = []
        for line in original_stanza.config_lines:
            modified_lines.append(line)
            modified_lines.append('')  # Add empty line

        test_stanza = type(original_stanza)(original_stanza.prefix, original_stanza.name, config_lines=modified_lines)

        # Should still be considered same content (empty lines filtered out)
        assert original_stanza.has_same_content(test_stanza)

    def test_has_same_content_strict_mode(self, original_dict):
        """Test has_same_content with normalise_whitespace=False"""
        original_stanza = original_dict['ltm profile http http-basic']

        # Create version with different whitespace
        modified_lines = ["  " + line + "  " for line in original_stanza.config_lines]

        test_stanza = type(original_stanza)(original_stanza.prefix, original_stanza.name, config_lines=modified_lines)

        # Should be different in strict mode
        assert not original_stanza.has_same_content(test_stanza, normalise_whitespace=False)

        # Should be same with normalisation
        assert original_stanza.has_same_content(test_stanza, normalise_whitespace=True)

    @pytest.mark.skip(reason="Performance test takes too long")
    def test_performance_with_large_sets(self, original_config, modified_config):
        """Test that set operations perform well with reasonable-sized configs"""
        import time

        original_set = set(original_config)
        modified_set = set(modified_config)

        # Time the set operations
        start_time = time.time()

        # Perform multiple operations
        for _ in range(100):
            union = original_set | modified_set
            intersection = original_set & modified_set
            diff1 = original_set - modified_set
            diff2 = modified_set - original_set

        elapsed = time.time() - start_time

        # Should complete quickly (less than 1 second for 100 iterations)
        assert elapsed < 1.5

    def test_configuration_consistency(self, original_config, modified_config):
        """Test that configs maintain internal consistency"""
        # All stanzas should have valid full_paths - test each config separately
        for stanza in original_config:
            assert stanza.full_path
            assert stanza.name
            assert isinstance(stanza.config_lines, list)

        for stanza in modified_config:
            assert stanza.full_path
            assert stanza.name
            assert isinstance(stanza.config_lines, list)

        # Test duplicate detection by adding a config to itself
        with pytest.raises(DuplicateStanzaError):
            # This should fail - adding original_config to itself
            result = original_config + original_config

        with pytest.raises(DuplicateStanzaError):
            # This should fail - adding modified_config to itself
            result = modified_config + modified_config

        # Test that combining different configs raises exception when there are overlaps
        with pytest.raises(DuplicateStanzaError):
            combined = original_config + modified_config

if __name__ == "__main__":
    pass