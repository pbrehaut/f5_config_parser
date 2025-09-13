import pytest
from f5_config_parser.collection import StanzaCollection
from pathlib import Path

class TestGetDefaultRd:
    """Test cases for the get_default_rd method."""

    @pytest.fixture
    def f5_config_obj(self):
        """Load the F5 configuration from the test data file."""
        INPUT_FILE = '../data/f5_scf_file_with_partitions.txt'

        test_dir = Path(__file__).parent
        with open(test_dir / INPUT_FILE, 'r') as f:
            config_text = f.read()

        return StanzaCollection.from_config(config_text)

    @pytest.fixture
    def all_stanzas(self, f5_config_obj):
        """Get all stanzas collection from the F5 configuration."""
        return f5_config_obj

    def test_partition_web_tier_returns_10(self, all_stanzas):
        """Test that web-tier partition returns default-route-domain 10."""
        web_tier_partition = None
        for stanza in all_stanzas:
            if stanza.prefix == ("auth", "partition") and stanza.name == "web-tier":
                web_tier_partition = stanza
                break

        assert web_tier_partition is not None
        result = web_tier_partition.get_default_rd(all_stanzas)
        assert result == "10"

    def test_partition_app_tier_returns_20(self, all_stanzas):
        """Test that app-tier partition returns default-route-domain 20."""
        app_tier_partition = None
        for stanza in all_stanzas:
            if stanza.prefix == ("auth", "partition") and stanza.name == "app-tier":
                app_tier_partition = stanza
                break

        assert app_tier_partition is not None
        result = app_tier_partition.get_default_rd(all_stanzas)
        assert result == "20"

    def test_partition_db_tier_returns_30(self, all_stanzas):
        """Test that db-tier partition returns default-route-domain 30."""
        db_tier_partition = None
        for stanza in all_stanzas:
            if stanza.prefix == ("auth", "partition") and stanza.name == "db-tier":
                db_tier_partition = stanza
                break

        assert db_tier_partition is not None
        result = db_tier_partition.get_default_rd(all_stanzas)
        assert result == "30"

    def test_partition_api_tier_returns_40(self, all_stanzas):
        """Test that api-tier partition returns default-route-domain 40."""
        api_tier_partition = None
        for stanza in all_stanzas:
            if stanza.prefix == ("auth", "partition") and stanza.name == "api-tier":
                api_tier_partition = stanza
                break

        assert api_tier_partition is not None
        result = api_tier_partition.get_default_rd(all_stanzas)
        assert result == "40"

    def test_partition_mgmt_tier_returns_0(self, all_stanzas):
        """Test that mgmt-tier partition (no default-route-domain) returns '0'."""
        mgmt_tier_partition = None
        for stanza in all_stanzas:
            if stanza.prefix == ("auth", "partition") and stanza.name == "mgmt-tier":
                mgmt_tier_partition = stanza
                break

        assert mgmt_tier_partition is not None
        result = mgmt_tier_partition.get_default_rd(all_stanzas)
        assert result == "0"

    def test_virtual_server_in_web_tier_returns_10(self, all_stanzas):
        """Test that virtual server in web-tier returns 10."""
        vs_web_basic = None
        for stanza in all_stanzas:
            if stanza.prefix == ("ltm", "virtual") and stanza.name == "/web-tier/vs-web-basic":
                vs_web_basic = stanza
                break

        assert vs_web_basic is not None
        result = vs_web_basic.get_default_rd(all_stanzas)
        assert result == "10"

    def test_virtual_server_in_app_tier_returns_20(self, all_stanzas):
        """Test that virtual server in app-tier returns 20."""
        vs_app_custom = None
        for stanza in all_stanzas:
            if stanza.prefix == ("ltm", "virtual") and stanza.name == "/app-tier/vs-app-custom":
                vs_app_custom = stanza
                break

        assert vs_app_custom is not None
        result = vs_app_custom.get_default_rd(all_stanzas)
        assert result == "20"

    def test_virtual_server_in_api_tier_returns_40(self, all_stanzas):
        """Test that virtual server in api-tier returns 40."""
        vs_api_gateway = None
        for stanza in all_stanzas:
            if stanza.prefix == ("ltm", "virtual") and stanza.name == "/api-tier/vs-api-gateway":
                vs_api_gateway = stanza
                break

        assert vs_api_gateway is not None
        result = vs_api_gateway.get_default_rd(all_stanzas)
        assert result == "40"

    def test_virtual_server_in_db_tier_returns_30(self, all_stanzas):
        """Test that virtual server in db-tier returns 30."""
        vs_database = None
        for stanza in all_stanzas:
            if stanza.prefix == ("ltm", "virtual") and stanza.name == "/db-tier/vs-database":
                vs_database = stanza
                break

        assert vs_database is not None
        result = vs_database.get_default_rd(all_stanzas)
        assert result == "30"

    def test_virtual_server_in_mgmt_tier_returns_0(self, all_stanzas):
        """Test that virtual server in mgmt-tier (no default-route-domain) returns '0'."""
        vs_dns = None
        for stanza in all_stanzas:
            if stanza.prefix == ("ltm", "virtual") and stanza.name == "/mgmt-tier/vs-dns":
                vs_dns = stanza
                break

        assert vs_dns is not None
        result = vs_dns.get_default_rd(all_stanzas)
        assert result == "0"

    def test_virtual_server_without_partition_returns_0(self, all_stanzas):
        """Test that virtual server without partition returns '0'."""
        vs_no_partition = None
        for stanza in all_stanzas:
            if stanza.prefix == ("ltm", "virtual") and stanza.name == "vs-no-partition":
                vs_no_partition = stanza
                break

        assert vs_no_partition is not None
        result = vs_no_partition.get_default_rd(all_stanzas)
        assert result == "0"

    def test_pool_in_web_tier_returns_10(self, all_stanzas):
        """Test that pool in web-tier returns 10."""
        pool_web_http = None
        for stanza in all_stanzas:
            if stanza.prefix == ("ltm", "pool") and stanza.name == "/web-tier/pool-web-http":
                pool_web_http = stanza
                break

        assert pool_web_http is not None
        result = pool_web_http.get_default_rd(all_stanzas)
        assert result == "10"

    def test_pool_in_api_tier_returns_40(self, all_stanzas):
        """Test that pool in api-tier returns 40."""
        pool_api = None
        for stanza in all_stanzas:
            if stanza.prefix == ("ltm", "pool") and stanza.name == "/api-tier/pool-api-multi-monitor":
                pool_api = stanza
                break

        assert pool_api is not None
        result = pool_api.get_default_rd(all_stanzas)
        assert result == "40"

    def test_pool_without_partition_returns_0(self, all_stanzas):
        """Test that pool without partition returns '0'."""
        pool_no_partition = None
        for stanza in all_stanzas:
            if stanza.prefix == ("ltm", "pool") and stanza.name == "pool-no-partition":
                pool_no_partition = stanza
                break

        assert pool_no_partition is not None
        result = pool_no_partition.get_default_rd(all_stanzas)
        assert result == "0"

    def test_node_in_web_tier_returns_10(self, all_stanzas):
        """Test that node in web-tier returns 10."""
        node_web_01 = None
        for stanza in all_stanzas:
            if stanza.prefix == ("ltm", "node") and stanza.name == "/web-tier/node-web-01":
                node_web_01 = stanza
                break

        assert node_web_01 is not None
        result = node_web_01.get_default_rd(all_stanzas)
        assert result == "10"

    def test_node_in_app_tier_returns_20(self, all_stanzas):
        """Test that node in app-tier returns 20."""
        node_app_01 = None
        for stanza in all_stanzas:
            if stanza.prefix == ("ltm", "node") and stanza.name == "/app-tier/node-app-01":
                node_app_01 = stanza
                break

        assert node_app_01 is not None
        result = node_app_01.get_default_rd(all_stanzas)
        assert result == "20"

    def test_monitor_in_web_tier_returns_10(self, all_stanzas):
        """Test that monitor in web-tier returns 10."""
        mon_http_basic = None
        for stanza in all_stanzas:
            if stanza.prefix == ("ltm", "monitor", "http") and stanza.name == "/web-tier/mon-http-basic":
                mon_http_basic = stanza
                break

        assert mon_http_basic is not None
        result = mon_http_basic.get_default_rd(all_stanzas)
        assert result == "10"

    def test_profile_in_api_tier_returns_40(self, all_stanzas):
        """Test that profile in api-tier returns 40."""
        http_oneconnect = None
        for stanza in all_stanzas:
            if stanza.prefix == ("ltm", "profile", "http") and stanza.name == "/api-tier/http-oneconnect":
                http_oneconnect = stanza
                break

        assert http_oneconnect is not None
        result = http_oneconnect.get_default_rd(all_stanzas)
        assert result == "40"

    def test_irule_in_web_tier_returns_10(self, all_stanzas):
        """Test that iRule in web-tier returns 10."""
        irule_redirect = None
        for stanza in all_stanzas:
            if stanza.prefix == ("ltm", "rule") and stanza.name == "/web-tier/irule-redirect-https":
                irule_redirect = stanza
                break

        assert irule_redirect is not None
        result = irule_redirect.get_default_rd(all_stanzas)
        assert result == "10"

    def test_all_partition_objects_return_expected_values(self, all_stanzas):
        """Test all partition objects return their expected default route domains."""
        expected_partitions = {
            "web-tier": "10",
            "app-tier": "20",
            "db-tier": "30",
            "api-tier": "40",
            "mgmt-tier": "0"
        }

        found_partitions = {}
        for stanza in all_stanzas:
            if stanza.prefix == ("auth", "partition"):
                result = stanza.get_default_rd(all_stanzas)
                found_partitions[stanza.name] = result

        for partition_name, expected_rd in expected_partitions.items():
            assert partition_name in found_partitions, f"Partition {partition_name} not found"
            assert found_partitions[partition_name] == expected_rd, \
                f"Partition {partition_name} returned {found_partitions[partition_name]}, expected {expected_rd}"

    def test_all_partitioned_objects_return_valid_values(self, all_stanzas):
        """Test that all objects with partition names return valid route domain values."""
        partitioned_objects = []

        for stanza in all_stanzas:
            if stanza.name.startswith('/') and stanza.prefix != ("auth", "partition"):
                result = stanza.get_default_rd(all_stanzas)
                partition_name = stanza.name.split('/')[1]
                partitioned_objects.append({
                    'stanza': stanza,
                    'partition': partition_name,
                    'result': result
                })

        assert len(partitioned_objects) > 0, "No partitioned objects found"

        # Check that each partitioned object returns the expected value based on its partition
        partition_domains = {
            "web-tier": "10",
            "app-tier": "20",
            "db-tier": "30",
            "api-tier": "40",
            "mgmt-tier": "0"
        }

        for obj in partitioned_objects:
            expected = partition_domains.get(obj['partition'], "0")
            assert obj['result'] == expected, \
                f"Object {obj['stanza'].name} in partition {obj['partition']} returned {obj['result']}, expected {expected}"

    def test_non_partitioned_objects_return_0(self, all_stanzas):
        """Test that objects without partition names return '0'."""
        non_partitioned_objects = []

        for stanza in all_stanzas:
            if not stanza.name.startswith('/') and stanza.prefix != ("auth", "partition"):
                result = stanza.get_default_rd(all_stanzas)
                non_partitioned_objects.append({
                    'name': stanza.name,
                    'prefix': stanza.prefix,
                    'result': result
                })

        assert len(non_partitioned_objects) > 0, "No non-partitioned objects found"

        for obj in non_partitioned_objects:
            assert obj['result'] == "0", \
                f"Non-partitioned object {obj['name']} returned {obj['result']}, expected '0'"

    def test_specific_objects_by_type(self, all_stanzas):
        """Test specific object types return correct values."""
        test_cases = [
            # Virtual servers
            ("/web-tier/vs-web-basic", ("ltm", "virtual"), "10"),
            ("/app-tier/vs-app-custom", ("ltm", "virtual"), "20"),
            ("/api-tier/vs-api-gateway", ("ltm", "virtual"), "40"),
            ("vs-no-partition", ("ltm", "virtual"), "0"),

            # Pools
            ("/web-tier/pool-web-http", ("ltm", "pool"), "10"),
            ("/app-tier/pool-app-tcp", ("ltm", "pool"), "20"),
            ("/api-tier/pool-api-multi-monitor", ("ltm", "pool"), "40"),
            ("pool-no-partition", ("ltm", "pool"), "0"),

            # Nodes
            ("/web-tier/node-web-01", ("ltm", "node"), "10"),
            ("/app-tier/node-app-01", ("ltm", "node"), "20"),
            ("/api-tier/node-api-01", ("ltm", "node"), "40"),
        ]

        for object_name, object_prefix, expected_result in test_cases:
            found_object = None
            for stanza in all_stanzas:
                if stanza.prefix == object_prefix and stanza.name == object_name:
                    found_object = stanza
                    break

            assert found_object is not None, f"Object {object_name} with prefix {object_prefix} not found"

            result = found_object.get_default_rd(all_stanzas)
            assert result == expected_result, \
                f"Object {object_name} returned {result}, expected {expected_result}"

    def test_method_returns_string_for_all_objects(self, all_stanzas):
        """Test that get_default_rd returns a string for every object."""
        tested_count = 0

        for stanza in all_stanzas:
            result = stanza.get_default_rd(all_stanzas)
            assert isinstance(result, str), f"Object {stanza.name} returned {type(result)}, expected str"
            assert result.isdigit(), f"Object {stanza.name} returned non-digit string: '{result}'"
            tested_count += 1

        assert tested_count > 0, "No objects were tested"
        print(f"Successfully tested {tested_count} objects")