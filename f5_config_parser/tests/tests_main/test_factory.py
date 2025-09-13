import pytest
from pathlib import Path
from f5_config_parser.factory import StanzaFactory
from f5_config_parser.stanza import ConfigStanza


class TestStanzaFactoryBasic:

    @pytest.fixture
    def sample_f5_config(self):
        """Basic F5 config for initial testing"""
        return """
ltm pool /Common/test-pool {
    description "Test pool"
    load-balancing-mode least-connections-member
    members {
        /Common/server01:8080 {
            address 192.168.1.10
        }
        /Common/server02:8080 {
            address 192.168.1.11
        }
    }
    monitor /Common/http
}

ltm virtual /Common/test-vs {
    destination 10.0.1.100:443
    ip-protocol tcp
    pool /Common/test-pool
    profiles {
        /Common/tcp { }
        /Common/http { }
    }
}

ltm rule /Common/redirect-rule {
    when HTTP_REQUEST {
        if { [HTTP::host] eq "oldsite.com" } {
            HTTP::redirect "https://newsite.com[HTTP::uri]"
        }
    }
}
"""

    def test_parse_basic_config(self, sample_f5_config):
        """Test that factory can parse basic F5 configuration"""
        stanzas = StanzaFactory.parse_stanzas(sample_f5_config)

        # Should get 3 stanzas
        assert len(stanzas) == 3

        # Check stanza types and names
        pool_stanza = stanzas[0]
        vs_stanza = stanzas[1]
        rule_stanza = stanzas[2]

        assert pool_stanza.prefix == ("ltm", "pool")
        assert pool_stanza.name == "/Common/test-pool"
        assert pool_stanza.full_path == "ltm pool /Common/test-pool"

        assert vs_stanza.prefix == ("ltm", "virtual")
        assert vs_stanza.name == "/Common/test-vs"

        assert rule_stanza.prefix == ("ltm", "rule")
        assert rule_stanza.name == "/Common/redirect-rule"

        # Basic content check
        assert len(pool_stanza.config_lines) > 0
        assert any("description" in line for line in pool_stanza.config_lines)

    def test_parse_from_file(self):
        """Test parsing from external file - replace 'sample_config.txt' with your file"""
        # Replace 'sample_config.txt' with your actual F5 config file
        config_file = "../data/f5_scf_config.txt"

        try:
            test_dir = Path(__file__).parent
            with open(test_dir / config_file, 'r') as f:
                config_content = f.read()

            stanzas = StanzaFactory.parse_stanzas(config_content)

            # Basic validation
            assert len(stanzas) > 0
            print(f"Parsed {len(stanzas)} stanzas from {config_file}")

            # Print first few stanzas for inspection
            for i, stanza in enumerate(stanzas[:5]):  # First 5 stanzas
                print(f"Stanza {i + 1}: {stanza.full_path}")
                print(f"  Content lines: {len(stanza.config_lines)}")

            parsed_stanzas = {x.full_path :x.parsed_config for x in stanzas}
            pass

        except FileNotFoundError:
            pytest.skip(f"Config file '{config_file}' not found - update path in test")

    def test_single_stanza_parsing(self):
        """Test that single stanza can be parsed"""
        single_stanza_config = """
ltm pool /Common/single-test {
    monitor /Common/tcp
    description "Single stanza test"
}
"""
        stanzas = StanzaFactory.parse_stanzas(single_stanza_config)

        assert len(stanzas) == 1
        assert stanzas[0].name == "/Common/single-test"
        assert stanzas[0].prefix == ("ltm", "pool")


class TestStanzaFactoryEdgeCases:
    """Test edge cases and unusual configurations"""

    def test_empty_config(self):
        """Test parsing empty configuration"""
        stanzas = StanzaFactory.parse_stanzas("")
        assert len(stanzas) == 0

    def test_config_with_only_comments(self):
        """Test configuration with only comments and whitespace"""
        comment_config = """
# This is a comment
# Another comment

        # Indented comment
"""
        stanzas = StanzaFactory.parse_stanzas(comment_config)
        assert len(stanzas) == 0

    def test_config_with_mixed_content(self):
        """Test configuration with comments interspersed with stanzas"""
        mixed_config = """
# Global configuration comment
# F5 config generated on 2024-01-01

ltm pool /Common/web-pool {
    description "Web server pool"
    monitor /Common/http
}

# Virtual server configuration follows
ltm virtual /Common/web-vs {
    destination 10.0.1.100:80
    pool /Common/web-pool
}
"""
        stanzas = StanzaFactory.parse_stanzas(mixed_config)
        assert len(stanzas) == 2
        assert stanzas[0].prefix == ("ltm", "pool")
        assert stanzas[1].prefix == ("ltm", "virtual")

    def test_stanza_with_empty_braces(self):
        """Test stanzas with empty configuration blocks"""
        empty_block_config = """
ltm profile tcp /Common/empty-profile { }

ltm pool /Common/another-pool {
    description "Pool with empty members block"
    members { }
}
"""
        stanzas = StanzaFactory.parse_stanzas(empty_block_config)
        assert len(stanzas) == 2
        assert stanzas[0].name == "/Common/empty-profile"
        assert stanzas[1].name == "/Common/another-pool"

    def test_deeply_nested_configuration(self):
        """Test parsing deeply nested F5 configuration"""
        nested_config = """
ltm virtual /Common/complex-vs {
    profiles {
        /Common/tcp {
            context clientside
        }
        /Common/http {
            context serverside
            settings {
                max-header-size 32768
                max-requests 100
            }
        }
        /Common/clientssl {
            context clientside
            cert-key-chain {
                default {
                    cert /Common/server.crt
                    key /Common/server.key
                }
            }
        }
    }
    pool /Common/web-pool
}
"""
        stanzas = StanzaFactory.parse_stanzas(nested_config)
        assert len(stanzas) == 1
        stanza = stanzas[0]

        # Test that parsing works correctly

        parsed_config = stanza.parsed_config
        assert "profiles" in parsed_config
        assert "/Common/tcp" in parsed_config["profiles"]
        assert "/Common/http" in parsed_config["profiles"]

        # Test deeply nested access
        http_settings = parsed_config["profiles"]["/Common/http"]["settings"]
        assert http_settings["max-header-size"] == "32768"


class TestStanzaFactoryF5Modules:
    """Test parsing various F5 module configurations"""

    def test_gtm_configurations(self):
        """Test Global Traffic Manager configurations"""
        gtm_config = """
gtm pool /Common/gtm-pool {
    alternate-mode round-robin
    fallback-mode return-to-dns
    members {
        vs1 {
            server /Common/server1
        }
    }
}

gtm wideip /Common/example.com {
    pool-lb-mode preferred-member
    pools {
        /Common/gtm-pool {
            order 1
        }
    }
}
"""
        stanzas = StanzaFactory.parse_stanzas(gtm_config)
        assert len(stanzas) == 2
        assert stanzas[0].prefix == ("gtm", "pool")
        assert stanzas[1].prefix == ("gtm", "wideip")

    def test_security_configurations(self):
        """Test security module configurations"""
        security_config = """
security firewall rule-list /Common/test-rules {
    rules {
        rule1 {
            action accept
            source {
                addresses {
                    192.168.1.0/24 { }
                }
            }
        }
    }
}

asm policy /Common/web-policy {
    enforcement-mode blocking
    template /Common/POLICY_TEMPLATE_FUNDAMENTAL
}
"""
        stanzas = StanzaFactory.parse_stanzas(security_config)
        assert len(stanzas) == 2
        # "security firewall rule-list /Common/test-rules" → prefix=("security", "firewall", "rule-list"), name="/Common/test-rules"
        assert stanzas[0].prefix == ("security", "firewall", "rule-list")
        assert stanzas[0].name == "/Common/test-rules"
        # "asm policy /Common/web-policy" → prefix=("asm", "policy"), name="/Common/web-policy"
        assert stanzas[1].prefix == ("asm", "policy")
        assert stanzas[1].name == "/Common/web-policy"

    def test_system_configurations(self):
        """Test system module configurations"""
        sys_config = """
sys ntp {
    servers {
        time1.google.com { }
        time2.google.com { }
    }
    timezone Australia/Sydney
}

net vlan /Common/internal {
    interfaces {
        1.1 { }
        1.2 { }
    }
    tag 100
}
"""
        stanzas = StanzaFactory.parse_stanzas(sys_config)
        assert len(stanzas) == 2
        # "sys ntp" → prefix=("sys",), name="ntp" (based on current factory logic)
        assert stanzas[0].prefix == ("sys",)
        assert stanzas[0].name == "ntp"
        # "net vlan /Common/internal" → prefix=("net", "vlan"), name="/Common/internal"
        assert stanzas[1].prefix == ("net", "vlan")
        assert stanzas[1].name == "/Common/internal"


class TestStanzaFactoryiRuleParsing:
    """Test specific handling of iRule configurations with TCL code"""

    def test_simple_irule(self):
        """Test parsing basic iRule"""
        irule_config = """
ltm rule /Common/basic-redirect {
    when HTTP_REQUEST {
        HTTP::redirect "https://newsite.com"
    }
}
"""
        stanzas = StanzaFactory.parse_stanzas(irule_config)
        assert len(stanzas) == 1
        stanza = stanzas[0]
        assert stanza.prefix == ("ltm", "rule")
        assert "when HTTP_REQUEST" in '\n'.join(stanza.config_lines)

    def test_complex_irule_with_braces(self):
        """Test iRule with complex TCL containing braces that might confuse parser"""
        complex_irule = """
ltm rule /Common/complex-logic {
    when HTTP_REQUEST {
        set host [HTTP::host]
        set uri [HTTP::uri]

        if { $host eq "api.example.com" } {
            if { $uri starts_with "/v1/" } {
                pool /Common/api-v1-pool
            } elseif { $uri starts_with "/v2/" } {
                pool /Common/api-v2-pool
            } else {
                HTTP::respond 404 content "API version not supported"
            }
        } else {
            HTTP::redirect "https://www.example.com$uri"
        }
    }

    when HTTP_RESPONSE {
        if { [HTTP::status] == 200 } {
            HTTP::header insert "X-Custom-Header" "processed"
        }
    }
}

ltm pool /Common/next-pool {
    monitor /Common/http
}
"""
        stanzas = StanzaFactory.parse_stanzas(complex_irule)
        assert len(stanzas) == 2

        irule_stanza = stanzas[0]
        pool_stanza = stanzas[1]

        assert irule_stanza.prefix == ("ltm", "rule")
        assert pool_stanza.prefix == ("ltm", "pool")
        assert pool_stanza.name == "/Common/next-pool"

        # Verify iRule content is preserved correctly
        irule_content = '\n'.join(irule_stanza.config_lines)  # Updated: direct join instead of raw_content
        assert "when HTTP_REQUEST" in irule_content
        assert "when HTTP_RESPONSE" in irule_content
        assert 'elseif { $uri starts_with "/v2/"' in irule_content

    def test_irule_followed_by_other_stanzas(self):
        """Test that iRule parsing doesn't interfere with subsequent stanzas"""
        mixed_config = """
ltm rule /Common/test-rule {
    when HTTP_REQUEST {
        if { [HTTP::host] contains "test" } {
            HTTP::redirect "https://example.com"
        }
    }
}

ltm virtual /Common/test-vs {
    destination 10.0.1.100:443
    rules {
        /Common/test-rule
    }
}

ltm pool /Common/test-pool {
    members {
        192.168.1.10:80 { }
    }
}
"""
        stanzas = StanzaFactory.parse_stanzas(mixed_config)
        assert len(stanzas) == 3

        rule_stanza, vs_stanza, pool_stanza = stanzas

        assert rule_stanza.prefix == ("ltm", "rule")
        assert vs_stanza.prefix == ("ltm", "virtual")
        assert pool_stanza.prefix == ("ltm", "pool")

        # Verify each stanza has correct content
        assert "when HTTP_REQUEST" in '\n'.join(rule_stanza.config_lines)
        assert "destination 10.0.1.100:443" in '\n'.join(vs_stanza.config_lines)
        assert "192.168.1.10:80" in '\n'.join(pool_stanza.config_lines)


class TestStanzaFactoryContentValidation:
    """Test that parsed content is accurate and complete"""

    def test_content_line_preservation(self):
        """Test that all content lines are preserved correctly"""
        config = """
ltm pool /Common/detailed-pool {
    description "Detailed pool configuration"
    load-balancing-mode least-connections-member
    slow-ramp-time 120
    members {
        /Common/server01:8080 {
            address 192.168.1.10
            connection-limit 1000
            ratio 100
        }
        /Common/server02:8080 {
            address 192.168.1.11
            connection-limit 1000
            ratio 100
        }
    }
    monitor /Common/http and /Common/tcp
}
"""
        stanzas = StanzaFactory.parse_stanzas(config)
        assert len(stanzas) == 1

        pool_stanza = stanzas[0]
        content = '\n'.join(pool_stanza.config_lines)  # Updated: direct join instead of raw_content

        # Verify key content is present
        assert 'description "Detailed pool configuration"' in content
        assert "load-balancing-mode least-connections-member" in content
        assert "slow-ramp-time 120" in content
        assert "connection-limit 1000" in content
        assert "monitor /Common/http and /Common/tcp" in content

    def test_whitespace_preservation(self):
        """Test that significant whitespace is preserved"""
        config = """
ltm pool /Common/whitespace-test {
    description "Test    with    spaces"
    monitor /Common/http
}
"""
        stanzas = StanzaFactory.parse_stanzas(config)
        stanza = stanzas[0]

        # Find the description line and verify spaces are preserved
        desc_lines = [line for line in stanza.config_lines if "description" in line]
        assert len(desc_lines) == 1
        assert "Test    with    spaces" in desc_lines[0]

    def test_closing_brace_handling(self):
        """Test that closing braces are handled correctly"""
        config = """
ltm pool /Common/brace-test {
    description "Test closing braces"
    members {
        server1:80 { }
        server2:80 {
            address 192.168.1.2
        }
    }
}
"""
        stanzas = StanzaFactory.parse_stanzas(config)
        stanza = stanzas[0]

        # Verify that the content doesn't end with an isolated closing brace
        lines = stanza.config_lines
        # The last line should be the closing brace for the stanza
        assert lines[-1].strip() == "}"

        # But there should be content before it
        assert len(lines) > 1
        assert any("members" in line for line in lines)


class TestStanzaFactoryIntegration:
    """Integration tests combining factory with stanza functionality"""

    def test_factory_to_stanza_methods(self):
        """Test that factory-created stanzas work with GenericStanza methods"""
        config = """
ltm pool /Common/integration-test {
    description "Integration test pool"
    load-balancing-mode round-robin
    members {
        server1:80 {
            address 192.168.1.10
        }
        server2:80 {
            address 192.168.1.11
        }
    }
    monitor /Common/http
}
"""
        stanzas = StanzaFactory.parse_stanzas(config)
        stanza = stanzas[0]

        # Test base methods work
        assert isinstance(stanza, ConfigStanza)

        # Test config parsing - access parsed data directly

        parsed = stanza.parsed_config
        assert parsed["description"] == '"Integration test pool"'
        assert parsed["load-balancing-mode"] == "round-robin"
        assert "members" in parsed

        # Test nested structure access directly
        members_block = parsed["members"]
        assert members_block is not None
        assert "server1:80" in members_block
        assert "server2:80" in members_block

    def test_change_tracking_on_factory_stanzas(self):
        """Test that change tracking works on factory-created stanzas"""
        config = """
ltm pool /Common/change-test {
    monitor /Common/tcp
    description "Original description"
}
"""
        stanzas = StanzaFactory.parse_stanzas(config)
        stanza = stanzas[0]

        # Make a change
        changes_made = stanza.find_and_replace("/Common/tcp", "/Common/http", "word_boundary")

        assert changes_made == 1
        assert bool(stanza._changes)  # Updated: direct access instead of has_changes
        assert "/Common/http" in '\n'.join(stanza.config_lines)  # Updated: direct join instead of raw_content

        # Check change record
        changes = stanza._changes  # Updated: direct access instead of get_changes()
        assert len(changes) == 1
        assert changes[0].old_content.strip().endswith("tcp")
        assert changes[0].new_content.strip().endswith("http")