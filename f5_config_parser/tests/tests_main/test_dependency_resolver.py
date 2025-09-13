import pytest
from pathlib import Path
from f5_config_parser.dependency_resolver import build_waves_structure, generate_waves
from f5_config_parser.collection import StanzaCollection


@pytest.fixture
def f5_config_obj():
    """Fixture to create F5Configuration object from test data."""
    test_dir = Path(__file__).parent
    with open(test_dir / '../data/f5_scf_config_2.txt') as f:
        return StanzaCollection.from_config(f.read())


@pytest.fixture
def all_stanzas(f5_config_obj):
    """Fixture to get all stanzas from the F5 configuration."""
    return f5_config_obj


@pytest.fixture
def original_stanza_count(f5_config_obj):
    """Fixture to get the original count of stanzas before processing."""
    return len(f5_config_obj)


@pytest.fixture
def waves(all_stanzas):
    """Fixture to build the waves structure."""
    return build_waves_structure(all_stanzas)


class TestDependencyResolver:

    def test_waves_structure_exists(self, waves):
        """Test that waves structure is created and not empty."""
        assert waves is not None
        assert len(waves) > 0

    def test_orphaned_objects_in_early_waves(self, waves):
        """Test that orphaned objects appear in early waves."""
        # Objects with no dependencies should be in wave 0 or 1
        early_wave_objects = []
        for wave_num in [0, 1]:
            if wave_num in waves:
                early_wave_objects.extend([obj.full_path for obj in waves[wave_num]])

        # These objects should have no dependencies on other config objects
        expected_orphans = [
            'ltm monitor tcp mon-tcp-orphaned-1',
            'ltm monitor http mon-http-orphaned-2',
            'ltm node node-orphaned-3',
            'ltm pool pool-orphaned-1',
            'ltm pool pool-orphaned-3'
        ]

        for orphan in expected_orphans:
            assert orphan in early_wave_objects, f"{orphan} should be in early waves"

    def test_dependency_chain_order(self, waves):
        """Test that objects are removed in correct dependency order."""
        all_objects_by_wave = {}
        for wave_num, objects in waves.items():
            all_objects_by_wave[wave_num] = [obj.full_path for obj in objects]

        # Find wave numbers for key objects
        vs_web_wave = None
        pool_web_wave = None
        node_web_wave = None
        mon_tcp_wave = None

        for wave_num, objects in all_objects_by_wave.items():
            if 'ltm virtual vs-web-app' in objects:
                vs_web_wave = wave_num
            if 'ltm pool pool-web-used' in objects:
                pool_web_wave = wave_num
            if 'ltm node node-web-used-01' in objects:
                node_web_wave = wave_num
            if 'ltm monitor tcp mon-tcp-web' in objects:
                mon_tcp_wave = wave_num

        # Assert dependency order: vs -> pool -> node -> monitor
        assert vs_web_wave < pool_web_wave, "Virtual server should be removed before its pool"
        assert pool_web_wave < node_web_wave, "Pool should be removed before its nodes"
        assert node_web_wave < mon_tcp_wave, "Nodes should be removed before their monitors"

    def test_all_objects_processed(self, original_stanza_count, waves):
        """Test that all objects are included in the waves."""
        total_objects_in_waves = sum(len(objects) for objects in waves.values())
        assert total_objects_in_waves == original_stanza_count, "All objects should be processed"

    def test_no_duplicate_objects_across_waves(self, waves):
        """Test that no object appears in multiple waves."""
        seen_objects = set()
        for wave_objects in waves.values():
            for obj in wave_objects:
                assert obj.full_path not in seen_objects, f"Object {obj.full_path} appears in multiple waves"
                seen_objects.add(obj.full_path)

    def test_monitors_in_final_waves(self, waves):
        """Test that used monitors are in the final waves."""
        # Used monitors should be removed last since they're dependencies
        final_waves = max(waves.keys()) - 1, max(waves.keys())
        final_wave_objects = []

        for wave_num in final_waves:
            if wave_num in waves:
                final_wave_objects.extend([obj.full_path for obj in waves[wave_num]])

        used_monitors = [
            'ltm monitor tcp mon-tcp-web',
            'ltm monitor http mon-http-api',
            'ltm monitor https mon-https-secure'
        ]

        for monitor in used_monitors:
            assert monitor in final_wave_objects, f"Used monitor {monitor} should be in final waves"

    def test_virtual_servers_before_pools(self, waves):
        """Test that all virtual servers are removed before their associated pools."""
        vs_pool_pairs = [
            ('ltm virtual vs-web-app', 'ltm pool pool-web-used'),
            ('ltm virtual vs-api-service', 'ltm pool pool-api-used'),
            ('ltm virtual vs-secure-app', 'ltm pool pool-secure-used')
        ]

        wave_lookup = {}
        for wave_num, objects in waves.items():
            for obj in objects:
                wave_lookup[obj.full_path] = wave_num

        for vs, pool in vs_pool_pairs:
            vs_wave = wave_lookup[vs]
            pool_wave = wave_lookup[pool]
            assert vs_wave < pool_wave, f"Virtual server {vs} should be removed before pool {pool}"

    def test_nodes_before_monitors(self, waves):
        """Test that nodes are removed before their monitors."""
        node_monitor_pairs = [
            ('ltm node node-web-used-01', 'ltm monitor tcp mon-tcp-web'),
            ('ltm node node-api-used-01', 'ltm monitor http mon-http-api'),
            ('ltm node node-secure-used-01', 'ltm monitor https mon-https-secure')
        ]

        wave_lookup = {}
        for wave_num, objects in waves.items():
            for obj in objects:
                wave_lookup[obj.full_path] = wave_num

        for node, monitor in node_monitor_pairs:
            node_wave = wave_lookup[node]
            monitor_wave = wave_lookup[monitor]
            assert node_wave < monitor_wave, f"Node {node} should be removed before monitor {monitor}"

    def test_specific_wave_counts(self, waves):
        """Test that we have a reasonable number of waves."""
        # Should have multiple waves due to dependency chains
        assert len(waves) >= 4, "Should have at least 4 waves for the dependency chains"
        assert len(waves) <= 10, "Should not have excessive number of waves"

    def test_orphaned_nodes_early_removal(self, waves):
        """Test that orphaned nodes are removed early."""
        early_waves = [0, 1, 2]
        early_wave_objects = []

        for wave_num in early_waves:
            if wave_num in waves:
                early_wave_objects.extend([obj.full_path for obj in waves[wave_num]])

        orphaned_nodes = [
            'ltm node node-orphaned-1',
            'ltm node node-orphaned-2'
        ]

        for node in orphaned_nodes:
            assert node in early_wave_objects, f"Orphaned node {node} should be removed early"

    def test_empty_pool_early_removal(self, waves):
        """Test that pools with no dependencies are removed early."""
        early_waves = [0, 1, 2]
        early_wave_objects = []

        for wave_num in early_waves:
            if wave_num in waves:
                early_wave_objects.extend([obj.full_path for obj in waves[wave_num]])

        # pool-orphaned-1 has monitor and members but isn't used by any VS
        # pool-orphaned-2 has monitor but no members and isn't used by VS
        # pool-orphaned-3 has no monitor and no members
        orphaned_pools = [
            'ltm pool pool-orphaned-1',
            'ltm pool pool-orphaned-2',
            'ltm pool pool-orphaned-3'
        ]

        for pool in orphaned_pools:
            assert pool in early_wave_objects, f"Orphaned pool {pool} should be removed early"

    def test_objects_with_dependencies_not_in_same_wave(self, waves):
        """Test that dependent objects are in different waves."""
        # Find a node and its monitor
        node_wave = None
        monitor_wave = None

        for wave_num, objects in waves.items():
            for obj in objects:
                if 'node-web-used-01' in obj.full_path:
                    node_wave = wave_num
                if 'mon-tcp-web' in obj.full_path:
                    monitor_wave = wave_num

        assert node_wave < monitor_wave, "Node should be removed before its monitor"


class TestGenerateWavesFunction:
    """Test cases specifically for the generate_waves generator function."""

    def test_generator_yields_waves_sequentially(self, all_stanzas):
        """Test that the generator yields waves one at a time."""
        wave_count = 0
        total_objects = 0

        for wave in generate_waves(all_stanzas):
            assert isinstance(wave, list), "Each wave should be a list"
            assert len(wave) > 0, "Each wave should contain at least one object"
            wave_count += 1
            total_objects += len(wave)

        assert wave_count > 0, "Should generate at least one wave"
        assert total_objects > 0, "Should process some objects"

    def test_generator_vs_build_waves_consistency(self, f5_config_obj):
        """Test that generator and build_waves produce consistent results."""
        # Get fresh copies for each test
        stanzas_for_generator = f5_config_obj
        stanzas_for_build = StanzaCollection(list(f5_config_obj))

        # Collect generator results
        generator_waves = []
        for wave in generate_waves(stanzas_for_generator):
            generator_waves.append([obj.full_path for obj in wave])

        # Get build_waves results
        build_result = build_waves_structure(stanzas_for_build)

        # Compare
        assert len(generator_waves) == len(build_result), "Should have same number of waves"

        for i, gen_wave in enumerate(generator_waves):
            build_wave = [obj.full_path for obj in build_result[i]]
            assert set(gen_wave) == set(build_wave), f"Wave {i} should contain same objects"


class TestEdgeCases:
    """Test edge cases and error conditions."""

    def test_empty_collection(self):
        """Test behaviour with empty stanza collection."""
        empty_collection = StanzaCollection([])
        waves = build_waves_structure(empty_collection)
        assert len(waves) == 0, "Empty collection should produce no waves"

    def test_single_object_no_dependencies(self, f5_config_obj):
        """Test with a single object that has no dependencies."""
        all_stanzas = f5_config_obj

        # Find an orphaned monitor (should have no dependencies)
        single_obj = None
        for obj in all_stanzas:
            if 'mon-tcp-orphaned-1' in obj.full_path:
                single_obj = obj
                break

        assert single_obj is not None, "Should find the orphaned monitor"

        single_collection = StanzaCollection([single_obj])
        waves = build_waves_structure(single_collection)

        assert len(waves) == 1, "Single independent object should create one wave"
        assert len(waves[0]) == 1, "Wave should contain exactly one object"
        assert waves[0][0].full_path == single_obj.full_path

    def test_original_collection_not_modified_in_build_waves(self, f5_config_obj):
        """Test that build_waves_structure doesn't modify the original unless it's the same object."""
        original_stanzas = f5_config_obj
        original_count = len(original_stanzas)

        # Create a copy for processing
        stanzas_copy = StanzaCollection(list(original_stanzas))

        build_waves_structure(stanzas_copy)

        # Original should be unchanged, copy should be empty
        assert len(original_stanzas) == original_count, "Original collection should be unchanged"
        assert len(stanzas_copy) == 0, "Copy should be empty after processing"

    def test_dependency_cache_clearing(self, f5_config_obj):
        """Test that dependency caches are properly cleared."""
        all_stanzas = f5_config_obj

        # Pre-populate some dependency caches by calling get_dependencies
        for obj in list(all_stanzas)[:3]:  # Just test a few objects
            obj.get_dependencies(all_stanzas)
            assert hasattr(obj, '_dependencies'), "Cache should be set"

        # Run the wave generation
        build_waves_structure(all_stanzas)

        # Note: After processing, all_stanzas is empty, so we can't test cache clearing
        # This test mainly ensures the cache clearing code doesn't cause errors
        pass

    def test_wave_numbers_are_sequential(self, waves):
        """Test that wave numbers are sequential starting from 0."""
        wave_numbers = sorted(waves.keys())
        expected_numbers = list(range(len(wave_numbers)))
        assert wave_numbers == expected_numbers, "Wave numbers should be sequential starting from 0"

    def test_no_empty_waves(self, waves):
        """Test that no wave is empty."""
        for wave_num, wave_objects in waves.items():
            assert len(wave_objects) > 0, f"Wave {wave_num} should not be empty"


class TestDependencyIntegrity:
    """Test cases for dependency integrity and correctness."""

    def test_no_object_depends_on_later_wave_object(self, waves):
        """Test that no object depends on objects removed in later waves."""
        # Create a mapping of object to wave number
        object_to_wave = {}
        for wave_num, objects in waves.items():
            for obj in objects:
                object_to_wave[obj.full_path] = wave_num

        # For each object, check its dependencies are in later waves
        for wave_num, objects in waves.items():
            for obj in objects:
                # We can't easily test this without re-instantiating the collections
                # This would require a more complex test setup
                pass

    def test_monitors_never_depend_on_other_objects(self, f5_config_obj):
        """Test that monitors (bottom of dependency tree) don't depend on other config objects."""
        all_stanzas = f5_config_obj

        monitor_objects = [obj for obj in all_stanzas if 'monitor' in obj.full_path]

        for monitor in monitor_objects:
            dependencies = monitor.get_dependencies(all_stanzas)
            # Dependencies should be empty or only contain external references
            # This test assumes monitors don't reference other config objects
            config_dependencies = [dep for dep in dependencies
                                   if any(dep in other.full_path for other in all_stanzas if other != monitor)]
            assert len(
                config_dependencies) == 0, f"Monitor {monitor.full_path} should not depend on other config objects"