import pytest
import json
from datetime import datetime
from f5_config_parser.stanza import ConfigStanza, GenericStanza
from f5_config_parser.change_record import ChangeRecord


class TestConfigStanza:
    """Test the base ConfigStanza class"""

    def test_config_stanza_instantiation(self):
        """Test basic ConfigStanza instantiation"""
        config_lines = ["description test", "enabled true"]
        stanza = ConfigStanza(
            prefix=("ltm", "pool"),
            name="/Common/test-pool",
            config_lines=config_lines
        )

        assert stanza.prefix == ("ltm", "pool")
        assert stanza.name == "/Common/test-pool"
        assert stanza.config_lines == config_lines
        assert stanza._parsed_config is None
        assert len(stanza._changes) == 0

    def test_config_stanza_empty_instantiation(self):
        """Test instantiation with empty values"""
        stanza = ConfigStanza(
            prefix=(),
            name="",
            config_lines=[]
        )

        assert stanza.prefix == ()
        assert stanza.name == ""
        assert stanza.config_lines == []
        assert stanza._parsed_config is None

    def test_full_path_property(self):
        """Test the full_path property calculation"""
        stanza = ConfigStanza(
            prefix=("ltm", "virtual"),
            name="/Common/web-vs",
            config_lines=["destination 10.0.1.100:80"]
        )

        assert stanza.full_path == "ltm virtual /Common/web-vs"

    def test_full_path_empty_prefix(self):
        """Test full_path with empty prefix"""
        stanza = ConfigStanza(
            prefix=(),
            name="global-config",
            config_lines=["setting value"]
        )

        assert stanza.full_path == " global-config"

    def test_invalidate_cache(self):
        """Test cache invalidation method"""
        stanza = ConfigStanza(
            prefix=("test",),
            name="test",
            config_lines=["test line"]
        )

        # Manually set parsed config
        stanza._parsed_config = {"test": "value"}
        assert stanza._parsed_config is not None

        # Invalidate cache
        stanza._invalidate_cache()
        assert stanza._parsed_config is None

    def test_update_config_lines(self):
        """Test updating config lines invalidates cache"""
        stanza = ConfigStanza(
            prefix=("test",),
            name="test",
            config_lines=["old line"]
        )

        # Set some parsed config
        stanza._parsed_config = {"old": "value"}

        # Update config lines
        new_lines = ["new line", "another line"]
        stanza.config_lines = new_lines

        assert stanza.config_lines == new_lines
        assert stanza._parsed_config is None

    def test_append_config_line(self):
        """Test appending config line invalidates cache"""
        stanza = ConfigStanza(
            prefix=("test",),
            name="test",
            config_lines=["line 1"]
        )

        # Set some parsed config
        stanza._parsed_config = {"test": "value"}

        # Append line
        stanza.config_lines.append("line 2")

        assert stanza.config_lines == ["line 1", "line 2"]
        assert stanza._parsed_config is None


class TestGenericStanza:
    """Test the GenericStanza class functionality"""

    @pytest.fixture
    def pool_config_lines(self):
        """Sample pool configuration lines"""
        return [
            "description test-app-pool",
            "load-balancing-mode least-connections-member",
            "members {",
            "    /Common/server01:8080 {",
            "        address 192.168.1.10",
            "        priority-group 1",
            "    }",
            "    /Common/server02:8080 {",
            "        address 192.168.1.11",
            "        priority-group 1",
            "    }",
            "    /Common/server03:8080 {",
            "        address 192.168.1.12",
            "        priority-group 2",
            "    }",
            "}",
            "monitor /Common/http"
        ]

    @pytest.fixture
    def virtual_server_config_lines(self):
        """Sample virtual server configuration lines"""
        return [
            "destination 10.0.1.100:443",
            "ip-protocol tcp",
            "pool /Common/web_pool",
            "profiles {",
            "    /Common/tcp { }",
            "    /Common/http { }",
            "    /Common/clientssl {",
            "        context clientside",
            "    }",
            "}",
            "rules {",
            "    /Common/redirect_rule",
            "}"
        ]

    @pytest.fixture
    def simple_config_lines(self):
        """Simple key-value configuration for basic tests"""
        return [
            "name test-config",
            "enabled true",
            "timeout 300",
            "description simple test configuration"
        ]

    @pytest.fixture
    def pool_stanza(self, pool_config_lines):
        """GenericStanza instance with pool configuration"""
        return GenericStanza(
            prefix=("ltm", "pool"),
            name="/Common/test-pool",
            config_lines=pool_config_lines
        )

    @pytest.fixture
    def virtual_server_stanza(self, virtual_server_config_lines):
        """GenericStanza instance with virtual server configuration"""
        return GenericStanza(
            prefix=("ltm", "virtual"),
            name="/Common/test-vs",
            config_lines=virtual_server_config_lines
        )

    @pytest.fixture
    def simple_stanza(self, simple_config_lines):
        """GenericStanza with simple configuration"""
        return GenericStanza(
            prefix=("sys", "config"),
            name="simple",
            config_lines=simple_config_lines
        )

    def test_generic_stanza_instantiation(self):
        """Test basic GenericStanza instantiation"""
        config_lines = ["description test", "enabled true"]
        stanza = GenericStanza(
            prefix=("ltm", "pool"),
            name="/Common/test-pool",
            config_lines=config_lines
        )

        assert stanza.prefix == ("ltm", "pool")
        assert stanza.name == "/Common/test-pool"
        assert stanza.config_lines == config_lines
        assert stanza._parsed_config is None
        assert len(stanza._changes) == 0

    def test_lazy_parsing_behavior(self):
        """Test that parsing only happens when accessed"""
        stanza = GenericStanza(
            prefix=("ltm", "pool"),
            name="/Common/test",
            config_lines=["description test-pool"]
        )

        # Initially should be None
        assert stanza._parsed_config is None

        # First access should trigger parsing
        parsed = stanza.parsed_config
        assert stanza._parsed_config is not None
        assert parsed["description"] == "test-pool"

        # Second access should use cached result
        parsed2 = stanza.parsed_config
        assert parsed2 is parsed  # Same object reference

    def test_cache_invalidation_on_modification(self):
        """Test that cache is invalidated when config is modified"""
        stanza = GenericStanza(
            prefix=("ltm", "pool"),
            name="/Common/test",
            config_lines=["description old-description"]
        )

        # Parse initially
        parsed = stanza.parsed_config
        assert parsed["description"] == "old-description"

        # Modify config lines directly
        stanza.config_lines = ["description new-description"]

        # Cache should be invalidated
        assert stanza._parsed_config is None

        # New parse should have updated content
        new_parsed = stanza.parsed_config
        assert new_parsed["description"] == "new-description"

    def test_parse_config_simple_values(self, simple_stanza):
        """Test parsing simple key-value pairs"""
        parsed = simple_stanza.parsed_config

        assert parsed["name"] == "test-config"
        assert parsed["enabled"] == "true"
        assert parsed["timeout"] == "300"
        assert parsed["description"] == "simple test configuration"

    def test_parse_config_nested_structure(self, pool_stanza):
        """Test parsing nested brace structures"""
        parsed = pool_stanza.parsed_config

        # Check that members is a nested dictionary
        assert "members" in parsed
        assert isinstance(parsed["members"], dict)

        # Check individual member entries
        members = parsed["members"]
        assert "/Common/server01:8080" in members
        assert "/Common/server02:8080" in members
        assert "/Common/server03:8080" in members

        # Check nested member properties
        server01 = members["/Common/server01:8080"]
        assert server01["address"] == "192.168.1.10"
        assert server01["priority-group"] == "1"

        server03 = members["/Common/server03:8080"]
        assert server03["priority-group"] == "2"

    def test_parse_config_deep_nesting(self, virtual_server_stanza):
        """Test parsing multiple levels of nesting"""
        parsed = virtual_server_stanza.parsed_config

        # Check profiles block
        profiles = parsed["profiles"]
        assert "/Common/tcp" in profiles
        assert "/Common/clientssl" in profiles

        # Check deep nesting in clientssl profile
        clientssl = profiles["/Common/clientssl"]
        assert clientssl["context"] == "clientside"

    def test_get_config_value_convenience_method(self, pool_stanza):
        """Test the get_config_value convenience method"""
        assert pool_stanza.get_config_value("description") == "test-app-pool"
        assert pool_stanza.get_config_value("monitor") == "/Common/http"
        assert pool_stanza.get_config_value("nonexistent") is None

    def test_parsing_empty_config(self):
        """Test parsing with empty configuration"""
        stanza = GenericStanza(
            prefix=("test",),
            name="empty",
            config_lines=[]
        )

        parsed = stanza.parsed_config
        assert parsed == {}

    def test_parsing_comments_and_empty_lines(self):
        """Test that comments and empty lines are skipped"""
        config_lines = [
            "# This is a comment",
            "description test",
            "",
            "# Another comment",
            "enabled true",
            "   ",  # Line with just spaces
            "timeout 300"
        ]

        stanza = GenericStanza(
            prefix=("test",),
            name="test",
            config_lines=config_lines
        )

        parsed = stanza.parsed_config
        assert parsed["description"] == "test"
        assert parsed["enabled"] == "true"
        assert parsed["timeout"] == "300"
        # Comments should not appear in parsed output
        assert "# This is a comment" not in parsed

    def test_parsing_boolean_like_values(self):
        """Test parsing lines that look like boolean flags"""
        config_lines = [
            "flag-without-value",
            "another-flag",
            "setting with-value"
        ]

        stanza = GenericStanza(
            prefix=("test",),
            name="test",
            config_lines=config_lines
        )

        parsed = stanza.parsed_config
        assert parsed["flag-without-value"] is True
        assert parsed["another-flag"] is True
        assert parsed["setting"] == "with-value"

    @pytest.fixture
    def expected_pool_structure(self):
        """Expected parsed structure for pool configuration"""
        return {
            "description": "test-app-pool",
            "load-balancing-mode": "least-connections-member",
            "members": {
                "/Common/server01:8080": {
                    "address": "192.168.1.10",
                    "priority-group": "1"
                },
                "/Common/server02:8080": {
                    "address": "192.168.1.11",
                    "priority-group": "1"
                },
                "/Common/server03:8080": {
                    "address": "192.168.1.12",
                    "priority-group": "2"
                }
            },
            "monitor": "/Common/http"
        }

    def test_parse_config_full_structure(self, pool_stanza, expected_pool_structure):
        """Test that the complete parsed structure matches expected output"""
        parsed = pool_stanza.parsed_config
        assert parsed == expected_pool_structure

    def test_parse_config_full_structure_with_pretty_diff(self, pool_stanza, expected_pool_structure):
        """Test with better diff output on failure"""
        parsed = pool_stanza.parsed_config

        # This gives much better diff output in pytest when structures don't match
        assert json.dumps(parsed, sort_keys=True, indent=2) == json.dumps(
            expected_pool_structure, sort_keys=True, indent=2
        )

    def test_find_lines_containing_text(self, pool_stanza):
        """Test finding lines containing specific text"""
        address_lines = []
        for i, line in enumerate(pool_stanza.config_lines):
            if "address" in line:
                address_lines.append((i, line))

        assert len(address_lines) == 3
        # Check that we get (index, content) tuples
        indices, contents = zip(*address_lines)
        assert "        address 192.168.1.10" in contents
        assert "        address 192.168.1.11" in contents
        assert "        address 192.168.1.12" in contents

        # Verify we get the correct line indices as well
        assert all(isinstance(idx, int) for idx in indices)
        assert len(set(indices)) == 3  # All different indices

    def test_stanza_properties(self, pool_stanza):
        """Test basic stanza properties"""
        assert pool_stanza.full_path == "ltm pool /Common/test-pool"
        assert pool_stanza.prefix == ("ltm", "pool")
        assert pool_stanza.name == "/Common/test-pool"
        assert len(pool_stanza._changes) == 0


class TestFindAndReplace:
    """Test the find and replace functionality"""

    def test_find_and_replace_word_boundary(self):
        """Test word boundary matching in find and replace"""
        config_lines = [
            "description test-pool",
            "members server1 server2",
            "monitor http"
        ]

        stanza = GenericStanza(
            prefix=("ltm", "pool"),
            name="/Common/test",
            config_lines=config_lines
        )

        # Replace 'server1' with 'newserver1'
        modifications = stanza.find_and_replace("server1", "newserver1", "word_boundary")

        assert modifications == 1
        assert "members newserver1 server2" in stanza.config_lines
        assert len(stanza._changes) == 1

        # Cache should be invalidated
        assert stanza._parsed_config is None

    def test_find_and_replace_substring(self):
        """Test substring matching in find and replace"""
        config_lines = [
            "description test-application-pool",
            "monitor /Common/http_test"
        ]

        stanza = GenericStanza(
            prefix=("ltm", "pool"),
            name="/Common/test",
            config_lines=config_lines
        )

        # Replace 'test' substring with 'prod'
        modifications = stanza.find_and_replace("test", "prod", "substring")

        assert modifications == 2
        assert "description prod-application-pool" in stanza.config_lines
        assert "monitor /Common/http_prod" in stanza.config_lines

    def test_find_and_replace_whole_line(self):
        """Test whole line matching in find and replace"""
        config_lines = [
            "description old description",
            "enabled false",
            "timeout 300"
        ]

        stanza = GenericStanza(
            prefix=("test",),
            name="test",
            config_lines=config_lines
        )

        # Replace entire line
        modifications = stanza.find_and_replace("enabled false", "enabled true", "whole_line")

        assert modifications == 1
        assert "enabled true" in stanza.config_lines
        assert "enabled false" not in stanza.config_lines

    def test_find_and_replace_no_matches(self):
        """Test find and replace when no matches are found"""
        config_lines = ["description test", "enabled true"]

        stanza = GenericStanza(
            prefix=("test",),
            name="test",
            config_lines=config_lines
        )

        # Try to replace something that doesn't exist
        modifications = stanza.find_and_replace("nonexistent", "replacement", "word_boundary")

        assert modifications == 0
        assert len(stanza._changes) == 0
        # Cache should not be invalidated if no changes made
        # (Would need to access parsed_config first to test this properly)

    def test_change_record_creation(self):
        """Test that ChangeRecord objects are created correctly"""
        config_lines = ["description old-name"]

        stanza = GenericStanza(
            prefix=("test",),
            name="test",
            config_lines=config_lines
        )

        modifications = stanza.find_and_replace("old-name", "new-name", "substring")

        assert modifications == 1
        assert len(stanza._changes) == 1

        change = stanza._changes[0]
        assert isinstance(change, ChangeRecord)
        assert change.line_index == 0
        assert change.old_content == "description old-name"
        assert change.new_content == "description new-name"
        assert change.search_pattern == "old-name"
        assert change.replacement == "new-name"
        assert change.match_found == "old-name"