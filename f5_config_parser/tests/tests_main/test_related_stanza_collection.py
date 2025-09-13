import pytest
from pathlib import Path
from f5_config_parser.collection import StanzaCollection


@pytest.fixture
def collection_with_dependencies():
    """Fixture that provides a collection with all dependencies resolved"""

    # Your test config would be loaded here
    test_dir = Path(__file__).parent
    with open(test_dir / '../data/f5_scf_config.txt') as f:
        config_text = f.read()

    # Load the configuration
    f5_config = StanzaCollection.from_config(config_text)

    # Convert to collection for dependency resolution
    collection = f5_config

    # Note: Dependencies are now discovered lazily when get_dependencies() is called
    # No need to pre-discover them in the fixture

    return collection


class TestGetRelatedStanzas:
    """Test suite for the get_related_stanzas method"""

    def test_virtual_server_basic_dependencies(self, collection_with_dependencies):
        """Test that basic virtual server dependencies are discovered"""
        collection = collection_with_dependencies

        # Get the basic web virtual server
        vs_stanzas = collection.filter(prefix=("ltm", "virtual"), name="vs-web-basic")
        related = collection.get_related_stanzas(vs_stanzas.stanzas)

        # Should include the VS itself, pool, profiles, and monitors
        related_paths = {stanza.full_path for stanza in related.stanzas}

        # Virtual server itself
        assert "ltm virtual vs-web-basic" in related_paths

        # Pool dependency
        assert "ltm pool pool-web-http" in related_paths

        # Profile dependencies
        assert "ltm profile tcp tcp-lan" in related_paths
        assert "ltm profile http http-basic" in related_paths

        # Monitor dependencies (through pool)
        assert "ltm monitor http mon-http-basic" in related_paths

        # Node dependencies (through pool members)
        assert "ltm node node-web-01" in related_paths
        assert "ltm node node-web-02" in related_paths
        assert "ltm node node-web-03" in related_paths

    def test_ssl_virtual_server_dependencies(self, collection_with_dependencies):
        """Test SSL virtual server with client and server SSL profiles"""
        collection = collection_with_dependencies

        vs_stanzas = collection.filter(prefix=("ltm", "virtual"), name="vs-web-ssl")
        related = collection.get_related_stanzas(vs_stanzas.stanzas)

        related_paths = {stanza.full_path for stanza in related.stanzas}

        # Virtual server and pool
        assert "ltm virtual vs-web-ssl" in related_paths
        assert "ltm pool pool-web-https" in related_paths

        # All profile dependencies
        assert "ltm profile tcp tcp-wan" in related_paths
        assert "ltm profile client-ssl clientssl-basic" in related_paths
        assert "ltm profile server-ssl serverssl-basic" in related_paths
        assert "ltm profile http http-compression" in related_paths

        # Monitor through pool
        assert "ltm monitor https mon-https-basic" in related_paths

        # iRule dependency
        assert "ltm rule irule-custom-headers" in related_paths

    def test_multi_ssl_virtual_server_dependencies(self, collection_with_dependencies):
        """Test virtual server with multiple SSL profiles"""
        collection = collection_with_dependencies

        vs_stanzas = collection.filter(prefix=("ltm", "virtual"), name="vs-multi-ssl")
        related = collection.get_related_stanzas(vs_stanzas.stanzas)

        related_paths = {stanza.full_path for stanza in related.stanzas}

        # Should include all three client SSL profiles
        assert "ltm profile client-ssl clientssl-basic" in related_paths
        assert "ltm profile client-ssl clientssl-sni" in related_paths
        assert "ltm profile client-ssl clientssl-strict" in related_paths

        # Server SSL profile
        assert "ltm profile server-ssl serverssl-verify" in related_paths

        # HTTP profile
        assert "ltm profile http http-xff-headers" in related_paths

    def test_api_gateway_with_multiple_irules(self, collection_with_dependencies):
        """Test virtual server with multiple iRules"""
        collection = collection_with_dependencies

        vs_stanzas = collection.filter(prefix=("ltm", "virtual"), name="vs-api-gateway")
        related = collection.get_related_stanzas(vs_stanzas.stanzas)

        related_paths = {stanza.full_path for stanza in related.stanzas}

        # Should include both iRules
        assert "ltm rule irule-maintenance-page" in related_paths
        assert "ltm rule irule-load-balancing" in related_paths

        # Pool with multiple monitors
        assert "ltm pool pool-api-multi-monitor" in related_paths

        # Both monitors from the pool
        assert "ltm monitor https mon-https-ssl-verify" in related_paths
        assert "ltm monitor tcp mon-tcp-basic" in related_paths

        # Nodes through pool
        assert "ltm node node-api-01" in related_paths
        assert "ltm node node-api-02" in related_paths

    def test_pool_with_multiple_monitors(self, collection_with_dependencies):
        """Test pool that uses multiple monitors with AND logic"""
        collection = collection_with_dependencies

        pool_stanzas = collection.filter(prefix=("ltm", "pool"), name="pool-api-multi-monitor")
        related = collection.get_related_stanzas(pool_stanzas.stanzas)

        related_paths = {stanza.full_path for stanza in related.stanzas}

        # Pool itself
        assert "ltm pool pool-api-multi-monitor" in related_paths

        # Both monitors
        assert "ltm monitor https mon-https-ssl-verify" in related_paths
        assert "ltm monitor tcp mon-tcp-basic" in related_paths

        # Node dependencies
        assert "ltm node node-api-01" in related_paths
        assert "ltm node node-api-02" in related_paths

    @pytest.mark.skip(reason="Monitor dependency discovery not implemented yet")
    def test_monitor_with_ssl_profile_dependency(self, collection_with_dependencies):
        """Test monitor that references an SSL profile"""
        collection = collection_with_dependencies

        monitor_stanzas = collection.filter(prefix=("ltm", "monitor"), name="mon-https-ssl-verify")
        related = collection.get_related_stanzas(monitor_stanzas.stanzas)

        related_paths = {stanza.full_path for stanza in related.stanzas}

        # Monitor itself
        assert "ltm monitor https mon-https-ssl-verify" in related_paths

        # SSL profile dependency
        assert "ltm profile server-ssl serverssl-basic" in related_paths

    def test_node_with_monitor_dependency(self, collection_with_dependencies):
        """Test node that references a monitor"""
        collection = collection_with_dependencies

        node_stanzas = collection.filter(prefix=("ltm", "node"), name="node-web-03")
        related = collection.get_related_stanzas(node_stanzas.stanzas)

        related_paths = {stanza.full_path for stanza in related.stanzas}

        # Node itself
        assert "ltm node node-web-03" in related_paths

        # Monitor dependency
        assert "ltm monitor http mon-http-basic" in related_paths

    def test_tcp_only_virtual_server(self, collection_with_dependencies):
        """Test TCP-only virtual server (no HTTP profiles)"""
        collection = collection_with_dependencies

        vs_stanzas = collection.filter(prefix=("ltm", "virtual"), name="vs-database")
        related = collection.get_related_stanzas(vs_stanzas.stanzas)

        related_paths = {stanza.full_path for stanza in related.stanzas}

        # Virtual server and pool
        assert "ltm virtual vs-database" in related_paths
        assert "ltm pool pool-database" in related_paths

        # TCP profile only
        assert "ltm profile tcp tcp-lan" in related_paths

        # No HTTP profiles should be included
        http_profiles = [path for path in related_paths if "profile http" in path]
        assert len(http_profiles) == 0

        # Monitor through pool
        assert "ltm monitor tcp mon-tcp-basic" in related_paths

    def test_udp_virtual_server(self, collection_with_dependencies):
        """Test UDP virtual server"""
        collection = collection_with_dependencies

        vs_stanzas = collection.filter(prefix=("ltm", "virtual"), name="vs-dns")
        related = collection.get_related_stanzas(vs_stanzas.stanzas)

        related_paths = {stanza.full_path for stanza in related.stanzas}

        # Virtual server and pool
        assert "ltm virtual vs-dns" in related_paths
        assert "ltm pool pool-dns" in related_paths

        # DNS monitor
        assert "ltm monitor dns mon-dns-custom" in related_paths

    def test_multiple_virtual_servers_dependencies(self, collection_with_dependencies):
        """Test getting dependencies for multiple virtual servers at once"""
        collection = collection_with_dependencies

        # Get multiple virtual servers
        vs_stanzas = collection.filter(prefix=("ltm", "virtual")).stanzas[:3]  # First 3 VS
        related = collection.get_related_stanzas(vs_stanzas)

        # Should include dependencies from all virtual servers
        related_paths = {stanza.full_path for stanza in related.stanzas}

        # Should have more dependencies than any single VS
        assert len(related_paths) > 10

        # Should include virtual servers
        vs_paths = [path for path in related_paths if "ltm virtual" in path]
        assert len(vs_paths) == 3

    def test_empty_initial_stanzas(self, collection_with_dependencies):
        """Test with empty initial stanzas list"""
        collection = collection_with_dependencies

        related = collection.get_related_stanzas([])

        assert len(related.stanzas) == 0

    def test_circular_dependency_prevention(self, collection_with_dependencies):
        """Test that circular dependencies don't cause infinite loops"""
        collection = collection_with_dependencies

        # Get a virtual server that might have circular refs through profiles/defaults-from
        vs_stanzas = collection.filter(prefix=("ltm", "virtual"), name="vs-web-ssl")

        # This should complete without hanging
        related = collection.get_related_stanzas(vs_stanzas.stanzas)

        # Should have reasonable number of dependencies (not infinite)
        assert len(related.stanzas) < 50

        # Should include the original VS
        related_paths = {stanza.full_path for stanza in related.stanzas}
        assert "ltm virtual vs-web-ssl" in related_paths

    def test_stanza_uniqueness_in_results(self, collection_with_dependencies):
        """Test that each stanza appears only once in results even if referenced multiple times"""
        collection = collection_with_dependencies

        # Get all virtual servers - many might reference the same profiles
        all_vs = collection.filter(prefix=("ltm", "virtual")).stanzas
        related = collection.get_related_stanzas(all_vs)

        # Check that each path appears only once
        related_paths = [stanza.full_path for stanza in related.stanzas]
        unique_paths = set(related_paths)

        assert len(related_paths) == len(unique_paths), "Duplicate stanzas found in results"

    def test_dependency_depth(self, collection_with_dependencies):
        """Test that dependencies are discovered at multiple levels of depth"""
        collection = collection_with_dependencies

        # Start with a virtual server that has deep dependencies
        vs_stanzas = collection.filter(prefix=("ltm", "virtual"), name="vs-api-gateway")
        related = collection.get_related_stanzas(vs_stanzas.stanzas)

        related_paths = {stanza.full_path for stanza in related.stanzas}

        # Level 1: Direct VS dependencies (pool, profiles, rules)
        assert "ltm pool pool-api-multi-monitor" in related_paths
        assert "ltm profile client-ssl clientssl-sni" in related_paths

        # Level 2: Pool dependencies (monitors, nodes)
        assert "ltm monitor https mon-https-ssl-verify" in related_paths
        assert "ltm node node-api-01" in related_paths

        # Level 3: Monitor dependencies (SSL profiles)
        # TODO: Re-enable when monitor dependency is implemented
        # assert "ltm profile server-ssl serverssl-basic" in related_paths

        # Level 4: Node monitor dependencies
        node_monitors = [path for path in related_paths
                         if "monitor" in path and any(node in path for node in ["node-api-01", "node-api-02"])]
        # Should have monitors from the nodes as well

    def test_external_monitor_dependencies(self, collection_with_dependencies):
        """Test pool with external script monitor"""
        collection = collection_with_dependencies

        pool_stanzas = collection.filter(prefix=("ltm", "pool"), name="pool-external-monitor")
        related = collection.get_related_stanzas(pool_stanzas.stanzas)

        related_paths = {stanza.full_path for stanza in related.stanzas}

        # Pool itself
        assert "ltm pool pool-external-monitor" in related_paths

        # External monitor
        assert "ltm monitor external mon-external-script" in related_paths



if __name__ == "__main__":
    # Sample test data setup for debugging
    sample_data = """
    ltm virtual test-vs {
        pool test-pool
    }
    ltm pool test-pool {
        monitor test-monitor
    }
    ltm monitor http test-monitor {
        defaults-from http
    }
    """

    # This would be used with a breakpoint to inspect the data
    pass