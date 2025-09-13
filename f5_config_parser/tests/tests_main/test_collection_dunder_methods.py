import pytest
from pathlib import Path
from typing import List
from f5_config_parser.stanza import ConfigStanza
from f5_config_parser.collection import StanzaCollection, DuplicateStanzaError


class TestStanzaCollection:
    """Test suite for StanzaCollection collection operations"""

    @pytest.fixture
    def f5_config(self):
        """Load the test F5 configuration"""
        config_content = """# TMOS V17

ltm monitor http mon-http-basic {
    defaults-from http
    interval 30
    timeout 91
    send "GET / HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n"
    recv "200 OK"
}
ltm monitor http mon-http-custom {
    defaults-from http
    interval 15
    timeout 46
    send "GET /health HTTP/1.1\\r\\nHost: app.example.com\\r\\nUser-Agent: F5-Monitor\\r\\n\\r\\n"
    recv "healthy"
    recv-disable "maintenance"
}
ltm monitor https mon-https-basic {
    defaults-from https
    interval 30
    timeout 91
    send "GET /status HTTP/1.1\\r\\nHost: secure.example.com\\r\\n\\r\\n"
    recv "OK"
}
ltm monitor tcp mon-tcp-basic {
    defaults-from tcp
    interval 10
    timeout 31
}
ltm profile http http-basic {
    defaults-from http
}
ltm profile client-ssl clientssl-basic {
    defaults-from clientssl
    ciphers "ECDHE+AES-GCM:ECDHE+AES:!aNULL:!MD5:!DSS"
    options { "no-sslv2" "no-sslv3" "no-tlsv1" }
}
ltm profile server-ssl serverssl-basic {
    defaults-from serverssl
    server-name "backend.example.com"
}
ltm node node-web-01 {
    address 10.0.1.10
    monitor mon-http-basic
}
ltm node node-web-02 {
    address 10.0.1.11
    monitor mon-tcp-basic
}
ltm pool pool-web-http {
    monitor mon-http-basic
    load-balancing-mode round-robin
    members {
        node-web-01:80 {
            address 10.0.1.10
        }
        node-web-02:80 {
            address 10.0.1.11
        }
    }
}
ltm virtual vs-web-basic {
    destination 192.168.100.100:80
    ip-protocol tcp
    pool pool-web-http
    profiles {
        http-basic { }
    }
    source 0.0.0.0/0
}
ltm virtual vs-web-ssl {
    destination 192.168.100.101:443
    ip-protocol tcp
    pool pool-web-http
    profiles {
        clientssl-basic {
            context clientside
        }
        serverssl-basic {
            context serverside
        }
        http-basic { }
    }
    source 0.0.0.0/0
}"""

        return StanzaCollection.from_config(config_content)

    @pytest.fixture
    def all_stanzas(self, f5_config):
        """Get all stanzas from the test configuration"""
        return f5_config

    @pytest.fixture
    def empty_collection(self):
        """Create an empty StanzaCollection"""
        return StanzaCollection([])

    @pytest.fixture
    def single_stanza_collection(self, all_stanzas):
        """Create a collection with a single stanza"""
        http_monitor = all_stanzas.filter(prefix=('ltm', 'monitor'), name='mon-http-basic')
        return http_monitor

    @pytest.fixture
    def virtual_servers(self, all_stanzas):
        """Get all virtual server stanzas"""
        return all_stanzas.filter(prefix=('ltm', 'virtual'))

    @pytest.fixture
    def monitors(self, all_stanzas):
        """Get all monitor stanzas"""
        return all_stanzas.filter(prefix=('ltm', 'monitor'))

    @pytest.fixture
    def profiles(self, all_stanzas):
        """Get all profile stanzas"""
        return all_stanzas.filter(prefix=('ltm', 'profile'))

    # Test __contains__ method
    def test_contains_with_string_path(self, virtual_servers):
        """Test __contains__ with string full_path"""
        assert 'ltm virtual vs-web-basic' in virtual_servers
        assert 'ltm virtual vs-web-ssl' in virtual_servers
        assert 'ltm virtual nonexistent' not in virtual_servers

    def test_contains_with_stanza_object(self, virtual_servers, all_stanzas):
        """Test __contains__ with ConfigStanza object"""
        vs_basic = all_stanzas['ltm virtual vs-web-basic']
        vs_ssl = all_stanzas['ltm virtual vs-web-ssl']
        http_monitor = all_stanzas['ltm monitor http mon-http-basic']

        assert vs_basic in virtual_servers
        assert vs_ssl in virtual_servers
        assert http_monitor not in virtual_servers

    def test_contains_with_invalid_type(self, virtual_servers):
        """Test __contains__ with invalid type returns False"""
        assert 123 not in virtual_servers
        assert [] not in virtual_servers
        assert None not in virtual_servers

    # Test __add__ method (creates new collection)
    def test_add_single_stanza(self, virtual_servers, all_stanzas):
        """Test adding a single stanza"""
        http_monitor = all_stanzas['ltm monitor http mon-http-basic']
        result = virtual_servers + http_monitor

        assert len(result) == len(virtual_servers) + 1
        assert http_monitor in result
        assert len(virtual_servers) == 2  # Original unchanged

    def test_add_list_of_stanzas(self, virtual_servers, monitors):
        """Test adding a list of stanzas"""
        monitor_list = monitors.stanzas[:2]  # First two monitors
        result = virtual_servers + monitor_list

        assert len(result) == len(virtual_servers) + 2
        for monitor in monitor_list:
            assert monitor in result
        assert len(virtual_servers) == 2  # Original unchanged

    def test_add_another_collection(self, virtual_servers, monitors):
        """Test adding another StanzaCollection"""
        result = virtual_servers + monitors

        assert len(result) == len(virtual_servers) + len(monitors)
        # Check all original items are present
        for vs in virtual_servers:
            assert vs in result
        for monitor in monitors:
            assert monitor in result
        assert len(virtual_servers) == 2  # Original unchanged

    def test_add_prevents_duplicates(self, virtual_servers, all_stanzas):
        """Test that adding existing stanza raises DuplicateStanzaError"""
        existing_vs = all_stanzas['ltm virtual vs-web-basic']

        with pytest.raises(DuplicateStanzaError) as exc_info:
            result = virtual_servers + existing_vs

        # Check the error message contains the expected guidance
        assert "duplicate full_path" in str(exc_info.value)
        assert "overwrite the config_lines list attribute" in str(exc_info.value)
        assert existing_vs.full_path in str(exc_info.value)

    def test_add_empty_collection(self, virtual_servers, empty_collection):
        """Test adding empty collection"""
        result = virtual_servers + empty_collection
        assert len(result) == len(virtual_servers)

        result2 = empty_collection + virtual_servers
        assert len(result2) == len(virtual_servers)

    def test_add_invalid_type_raises_error(self, virtual_servers):
        """Test that adding invalid types raises TypeError"""
        with pytest.raises(TypeError, match="Unsupported type for collection operation"):
            virtual_servers + "invalid_string"

        with pytest.raises(TypeError, match="All items in list must be ConfigStanza objects"):
            virtual_servers + ["string", "another_string"]

        with pytest.raises(TypeError):
            virtual_servers + 123

    # Test __iadd__ method (in-place addition)
    def test_iadd_single_stanza(self, virtual_servers, all_stanzas):
        """Test in-place addition of single stanza"""
        original_id = id(virtual_servers)
        original_length = len(virtual_servers)
        http_monitor = all_stanzas['ltm monitor http mon-http-basic']

        virtual_servers += http_monitor

        assert id(virtual_servers) == original_id  # Same object
        assert len(virtual_servers) == original_length + 1
        assert http_monitor in virtual_servers

    def test_iadd_list_of_stanzas(self, profiles, monitors):
        """Test in-place addition of list of stanzas"""
        original_id = id(profiles)
        original_length = len(profiles)
        monitor_list = monitors.stanzas[:2]

        profiles += monitor_list

        assert id(profiles) == original_id  # Same object
        assert len(profiles) == original_length + 2
        for monitor in monitor_list:
            assert monitor in profiles

    def test_iadd_another_collection(self, virtual_servers, monitors):
        """Test in-place addition of another collection"""
        original_id = id(virtual_servers)
        original_length = len(virtual_servers)
        monitor_count = len(monitors)

        virtual_servers += monitors

        assert id(virtual_servers) == original_id  # Same object
        assert len(virtual_servers) == original_length + monitor_count

    def test_iadd_prevents_duplicates(self, virtual_servers, all_stanzas):
        """Test that in-place addition prevents duplicates"""
        original_length = len(virtual_servers)
        existing_vs = all_stanzas['ltm virtual vs-web-basic']
        with pytest.raises(DuplicateStanzaError) as exc_info:
            virtual_servers += existing_vs

        # Check the error message contains the expected guidance
        assert "duplicate full_path" in str(exc_info.value)
        assert "overwrite the config_lines list attribute" in str(exc_info.value)
        assert existing_vs.full_path in str(exc_info.value)
        assert len(virtual_servers) == original_length  # No change

    # Test __sub__ method (creates new collection)
    def test_sub_single_stanza(self, virtual_servers, all_stanzas):
        """Test subtracting a single stanza"""
        vs_to_remove = all_stanzas['ltm virtual vs-web-basic']
        result = virtual_servers - vs_to_remove

        assert len(result) == len(virtual_servers) - 1
        assert vs_to_remove not in result
        assert len(virtual_servers) == 2  # Original unchanged

    def test_sub_list_of_stanzas(self, all_stanzas, monitors):
        """Test subtracting a list of stanzas"""
        monitors_to_remove = monitors.stanzas[:2]
        result = all_stanzas - monitors_to_remove

        for monitor in monitors_to_remove:
            assert monitor not in result
        assert len(all_stanzas) > len(result)  # Original unchanged, result smaller

    def test_sub_another_collection(self, all_stanzas, monitors):
        """Test subtracting another collection"""
        result = all_stanzas - monitors

        for monitor in monitors:
            assert monitor not in result
        assert len(result) == len(all_stanzas) - len(monitors)

    def test_sub_nonexistent_stanza(self, virtual_servers, all_stanzas):
        """Test subtracting stanza that doesn't exist"""
        http_monitor = all_stanzas['ltm monitor http mon-http-basic']
        result = virtual_servers - http_monitor

        assert len(result) == len(virtual_servers)  # No change

    def test_sub_empty_collection(self, virtual_servers, empty_collection):
        """Test subtracting empty collection"""
        result = virtual_servers - empty_collection
        assert len(result) == len(virtual_servers)

    # Test __isub__ method (in-place subtraction)
    def test_isub_single_stanza(self, virtual_servers, all_stanzas):
        """Test in-place subtraction of single stanza"""
        original_id = id(virtual_servers)
        original_length = len(virtual_servers)
        vs_to_remove = all_stanzas['ltm virtual vs-web-basic']

        virtual_servers -= vs_to_remove

        assert id(virtual_servers) == original_id  # Same object
        assert len(virtual_servers) == original_length - 1
        assert vs_to_remove not in virtual_servers

    def test_isub_list_of_stanzas(self, all_stanzas, monitors):
        """Test in-place subtraction of list of stanzas"""
        original_id = id(all_stanzas)
        monitors_to_remove = monitors.stanzas[:2]
        original_length = len(all_stanzas)

        all_stanzas -= monitors_to_remove

        assert id(all_stanzas) == original_id  # Same object
        assert len(all_stanzas) == original_length - 2
        for monitor in monitors_to_remove:
            assert monitor not in all_stanzas

    def test_isub_another_collection(self, all_stanzas, monitors):
        """Test in-place subtraction of another collection"""
        original_id = id(all_stanzas)
        original_length = len(all_stanzas)
        monitor_count = len(monitors)

        all_stanzas -= monitors

        assert id(all_stanzas) == original_id  # Same object
        assert len(all_stanzas) == original_length - monitor_count

    def test_isub_nonexistent_stanza(self, virtual_servers, all_stanzas):
        """Test in-place subtraction of nonexistent stanza"""
        original_length = len(virtual_servers)
        http_monitor = all_stanzas['ltm monitor http mon-http-basic']

        virtual_servers -= http_monitor

        assert len(virtual_servers) == original_length  # No change

    # Test error handling for subtraction
    def test_sub_invalid_type_raises_error(self, virtual_servers):
        """Test that subtracting invalid types raises TypeError"""
        with pytest.raises(TypeError, match="Unsupported type for collection operation"):
            virtual_servers - "invalid_string"

        with pytest.raises(TypeError, match="All items in list must be ConfigStanza objects"):
            virtual_servers - ["string", "another_string"]

    # Test chaining operations
    def test_chained_operations(self, virtual_servers, monitors, profiles, all_stanzas):
        """Test chaining multiple operations"""
        # Add monitors, then subtract one specific monitor
        specific_monitor = all_stanzas['ltm monitor http mon-http-basic']
        result = (virtual_servers + monitors) - specific_monitor

        assert len(result) == len(virtual_servers) + len(monitors) - 1
        assert specific_monitor not in result

        # Test with profiles
        result2 = result + profiles
        assert len(result2) == len(result) + len(profiles)

    def test_mixed_operations_with_same_collection(self, virtual_servers, monitors):
        """Test adding and subtracting the same collection"""
        # Add monitors then subtract them
        result = (virtual_servers + monitors) - monitors

        # Should be back to original virtual servers
        assert len(result) == len(virtual_servers)
        for vs in virtual_servers:
            assert vs in result

    # Test edge cases
    def test_operations_with_single_item_collection(self, single_stanza_collection, all_stanzas):
        """Test operations with single-item collection"""
        vs_basic = all_stanzas['ltm virtual vs-web-basic']

        # Add to single item collection
        result = single_stanza_collection + vs_basic
        assert len(result) == 2

        # Subtract from single item collection
        result2 = single_stanza_collection - vs_basic  # vs_basic not in original
        assert len(result2) == 1  # No change

        # Subtract the actual item
        monitor = single_stanza_collection.stanzas[0]
        result3 = single_stanza_collection - monitor
        assert len(result3) == 0

    def test_operations_preserve_original_order(self, virtual_servers, monitors):
        """Test that operations preserve stanza order"""
        # Get specific order
        first_vs = virtual_servers.stanzas[0]
        second_vs = virtual_servers.stanzas[1]

        # Add and subtract, should maintain order
        result = (virtual_servers + monitors) - monitors

        assert result.stanzas[0].full_path == first_vs.full_path
        assert result.stanzas[1].full_path == second_vs.full_path

    # Integration tests with existing methods
    def test_operations_work_with_filter(self, all_stanzas):
        """Test that collection operations work with filter results"""
        http_monitors = all_stanzas.filter(prefix=('ltm', 'monitor', 'http'))
        tcp_monitors = all_stanzas.filter(prefix=('ltm', 'monitor', 'tcp'))

        # Combine filtered results
        all_monitors = http_monitors + tcp_monitors
        assert len(all_monitors) == len(http_monitors) + len(tcp_monitors)

        # Filter the combined result
        basic_monitors = all_monitors.filter(name='mon-http-basic')
        assert len(basic_monitors) <= len(all_monitors)

    def test_operations_work_with_get_related_stanzas(self, all_stanzas):
        """Test operations with get_related_stanzas results"""
        # Get a virtual server and its related stanzas
        vs_collection = all_stanzas.filter(prefix=('ltm', 'virtual'), name='vs-web-basic')
        related = all_stanzas.get_related_stanzas(vs_collection.stanzas)

        # Test operations on related stanzas
        additional_vs = all_stanzas.filter(prefix=('ltm', 'virtual'), name='vs-web-ssl')
        combined = related + additional_vs

        assert len(combined) >= len(related)
        for stanza in additional_vs:
            assert stanza in combined


# Test sample usage patterns
class TestStanzaCollectionUsagePatterns:
    """Test realistic usage patterns for StanzaCollection operations"""

    @pytest.fixture
    def f5_config(self):
        """Full F5 configuration for realistic testing"""
        test_dir = Path(__file__).parent
        with open(test_dir / '../data/f5_scf_config.txt') as f:
            return StanzaCollection.from_config(f.read())

    def test_build_deployment_set(self, f5_config):
        """Test building a deployment set by combining multiple filtered results"""
        all_stanzas = f5_config

        # Start with specific virtual servers
        web_vs = all_stanzas.filter(prefix=('ltm', 'virtual'), name='vs-web-basic')
        ssl_vs = all_stanzas.filter(prefix=('ltm', 'virtual'), name='vs-web-ssl')

        # Combine them
        deployment_vs = web_vs + ssl_vs
        assert len(deployment_vs) == 2

        # Add their dependencies
        deployment_set = all_stanzas.get_related_stanzas(deployment_vs.stanzas)

        # Should include pools, monitors, profiles, etc.
        assert len(deployment_set) > len(deployment_vs)

    def test_exclude_problematic_objects(self, f5_config):
        """Test excluding problematic objects from a deployment"""
        all_stanzas = f5_config

        # Get all virtual servers
        all_vs = all_stanzas.filter(prefix=('ltm', 'virtual'))

        # Exclude specific problematic ones
        problematic_vs = all_stanzas.filter(prefix=('ltm', 'virtual'), name='vs-database')
        clean_vs = all_vs - problematic_vs

        assert len(clean_vs) == len(all_vs) - len(problematic_vs)
        assert 'ltm virtual vs-database' not in clean_vs

    def test_environment_specific_filtering(self, f5_config):
        """Test building environment-specific configurations"""
        all_stanzas = f5_config

        # Get base web infrastructure
        web_infrastructure = all_stanzas.filter(prefix=('ltm', 'virtual')).filter(name='vs-web-basic')
        web_dependencies = all_stanzas.get_related_stanzas(web_infrastructure.stanzas)

        # Add environment-specific monitoring
        prod_monitors = all_stanzas.filter(prefix=('ltm', 'monitor')).filter(name='mon-external-script')

        # Combine for production deployment
        prod_config = web_dependencies + prod_monitors

        assert len(prod_config) >= len(web_dependencies)
        pass