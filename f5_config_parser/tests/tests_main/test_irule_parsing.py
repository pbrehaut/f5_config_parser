import pytest
from f5_config_parser.stanza import IRuleStanza
from f5_config_parser.stanza.irule_parser import parse_irule, is_conditional_line


class TestIRuleParserFunctions:
    """Test the standalone parser functions"""

    def test_is_conditional_line_basic_keywords(self):
        """Test detection of basic conditional keywords"""
        assert is_conditional_line("if { [HTTP::uri] starts_with \"/api/\" }")
        assert is_conditional_line("when HTTP_REQUEST {")
        assert is_conditional_line("else {")
        assert is_conditional_line("elsif { [HTTP::method] eq \"POST\" }")

    def test_is_conditional_line_with_closing_brace(self):
        """Test detection of conditionals after closing braces"""
        assert is_conditional_line("} else {")
        assert is_conditional_line("} elsif { [HTTP::header Host] eq \"api.com\" }")
        assert is_conditional_line("}else{")  # No spaces

    def test_is_conditional_line_negative_cases(self):
        """Test lines that should not be detected as conditional"""
        assert not is_conditional_line("pool /Common/web_pool")
        assert not is_conditional_line("HTTP::respond 200")
        assert not is_conditional_line("log local0. \"Request received\"")
        assert not is_conditional_line("}")  # Just closing brace
        assert not is_conditional_line("# if this is a comment")

    def test_parse_irule_empty_input(self):
        """Test parsing empty or whitespace-only input"""
        result = parse_irule([])
        assert result == {
            'irule_flow': [],
            'unique_words': [],
            'http_responses': []
        }

        result = parse_irule(["", "   ", "\t"])
        assert result == {
            'irule_flow': [],
            'unique_words': [],
            'http_responses': []
        }

    def test_parse_irule_comments_only(self):
        """Test parsing input with only comments"""
        lines = [
            "# This is a comment",
            "# Another comment",
            "#Yet another comment"
        ]
        result = parse_irule(lines)
        assert result == {
            'irule_flow': [],
            'unique_words': [],
            'http_responses': []
        }


class TestIRuleStanza:
    """Test the IRuleStanza class functionality"""

    @pytest.fixture
    def simple_irule_content(self):
        """Simple iRule with basic HTTP event"""
        return [
            "when HTTP_REQUEST {",
            "    if { [HTTP::uri] starts_with \"/api/\" } {",
            "        pool /Common/api_pool",
            "    } else {",
            "        pool /Common/web_pool",
            "    }",
            "}"
        ]

    @pytest.fixture
    def complex_irule_content(self):
        """Complex iRule with multiple events and logic"""
        return [
            "when CLIENT_ACCEPTED {",
            "    set client_ip [IP::client_addr]",
            "    log local0. \"Client connected: $client_ip\"",
            "}",
            "",
            "when HTTP_REQUEST {",
            "    if { [HTTP::header Host] eq \"api.example.com\" } {",
            "        HTTP::header insert \"X-Forwarded-Host\" [HTTP::header Host]",
            "        pool /Common/api_pool",
            "    } elsif { [HTTP::path] starts_with \"/admin\" } {",
            "        HTTP::respond 403 content \"Access Denied\"",
            "    } else {",
            "        pool /Common/default_pool",
            "    }",
            "}",
            "",
            "when HTTP_RESPONSE {",
            "    HTTP::header insert \"X-Server\" \"F5-BIG-IP\"",
            "}"
        ]

    @pytest.fixture
    def http_responses_irule(self):
        """iRule focused on HTTP responses and redirects"""
        return [
            "when HTTP_REQUEST {",
            "    if { [HTTP::path] eq \"/maintenance\" } {",
            "        HTTP::respond 503 content \"Service Unavailable\"",
            "    } elsif { [HTTP::path] eq \"/old-path\" } {",
            "        HTTP::redirect \"https://example.com/new-path\"",
            "    } elsif { [HTTP::path] eq \"/forbidden\" } {",
            "        HTTP::respond 403",
            "    }",
            "}"
        ]

    def test_irule_stanza_instantiation(self, simple_irule_content):
        """Test basic IRuleStanza creation"""
        irule = IRuleStanza(
            prefix=("ltm", "rule"),
            name="/Common/test_irule",
            config_lines=simple_irule_content
        )

        assert irule.prefix == ("ltm", "rule")
        assert irule.name == "/Common/test_irule"
        assert irule.config_lines == simple_irule_content
        assert irule._parsed_config is None

    def test_irule_lazy_parsing(self, simple_irule_content):
        """Test that iRule parsing uses the custom parser"""
        irule = IRuleStanza(
            prefix=("ltm", "rule"),
            name="/Common/test_irule",
            config_lines=simple_irule_content
        )

        # Should start with no parsed config
        assert irule._parsed_config is None

        # Accessing parsed_config should trigger custom parsing
        parsed = irule.parsed_config
        assert parsed is not None
        assert 'irule_flow' in parsed
        assert 'unique_words' in parsed
        assert 'http_responses' in parsed

    def test_simple_irule_parsing(self, simple_irule_content):
        """Test parsing of simple iRule structure"""
        irule = IRuleStanza(
            prefix=("ltm", "rule"),
            name="/Common/simple_test",
            config_lines=simple_irule_content
        )

        parsed = irule.parsed_config

        # Check unique_words contains pool names
        expected_pools = {'/Common/api_pool', '/Common/web_pool'}
        assert expected_pools.issubset(parsed['unique_words'])

        # Check irule_flow contains conditional context
        flow = parsed['irule_flow']
        assert len(flow) == 2

        # Should have conditional context in flow
        api_pool_action = next((f for f in flow if 'api_pool' in f), None)
        web_pool_action = next((f for f in flow if 'web_pool' in f), None)

        assert api_pool_action is not None
        assert web_pool_action is not None
        assert 'when HTTP_REQUEST' in api_pool_action
        assert 'if' in api_pool_action
        assert 'else' in web_pool_action

    def test_complex_irule_parsing(self, complex_irule_content):
        """Test parsing of complex iRule with multiple events"""
        irule = IRuleStanza(
            prefix=("ltm", "rule"),
            name="/Common/complex_test",
            config_lines=complex_irule_content
        )

        parsed = irule.parsed_config

        # Check unique_words contains pool names
        expected_pools = {'/Common/api_pool', '/Common/default_pool'}
        assert expected_pools.issubset(parsed['unique_words'])

        # Check HTTP responses
        http_responses = parsed['http_responses']
        assert len(http_responses) == 1
        assert 'HTTP::respond 403 content "Access Denied"' in http_responses

        # Check irule_flow
        flow = parsed['irule_flow']

        # Should have actions from different events
        client_accepted_actions = [f for f in flow if 'CLIENT_ACCEPTED' in f]
        http_request_actions = [f for f in flow if 'HTTP_REQUEST' in f]

        assert len(client_accepted_actions) == 1  # log action
        assert len(http_request_actions) == 3  # 2 pool actions + HTTP::respond

    def test_http_responses_parsing(self, http_responses_irule):
        """Test parsing of HTTP responses and redirects"""
        irule = IRuleStanza(
            prefix=("ltm", "rule"),
            name="/Common/http_test",
            config_lines=http_responses_irule
        )

        parsed = irule.parsed_config

        # Should have no pool names in unique_words
        pool_words = [word for word in parsed['unique_words'] if word.startswith('/Common/') and 'pool' in word.lower()]
        assert len(pool_words) == 0

        # Should have HTTP responses
        http_responses = parsed['http_responses']
        assert len(http_responses) == 3

        expected_responses = {
            'HTTP::respond 503 content "Service Unavailable"',
            'HTTP::redirect "https://example.com/new-path"',
            'HTTP::respond 403'
        }
        assert set(http_responses) == expected_responses

    def test_nested_conditionals_flow(self):
        """Test complex nested conditional flow tracking"""
        lines = [
            "when HTTP_REQUEST {",
            "    if { [HTTP::method] eq \"GET\" } {",
            "        if { [HTTP::uri] starts_with \"/secure\" } {",
            "            HTTP::respond 401",
            "        } else {",
            "            pool /Common/public_pool",
            "        }",
            "    } else {",
            "        pool /Common/post_pool",
            "    }",
            "}"
        ]

        irule = IRuleStanza(
            prefix=("ltm", "rule"),
            name="/Common/nested_test",
            config_lines=lines
        )

        parsed = irule.parsed_config
        flow = parsed['irule_flow']

        # Should track nested conditional context
        auth_action = next((f for f in flow if 'HTTP::respond 401' in f), None)
        public_action = next((f for f in flow if 'public_pool' in f), None)
        post_action = next((f for f in flow if 'post_pool' in f), None)

        assert auth_action is not None
        assert public_action is not None
        assert post_action is not None

        # Check that nested conditions are tracked
        assert 'when HTTP_REQUEST' in auth_action
        assert 'if { [HTTP::method] eq "GET" }' in auth_action
        assert 'if { [HTTP::uri] starts_with "/secure" }' in auth_action

    def test_actions_without_conditions(self):
        """Test actions that occur outside of conditional blocks"""
        lines = [
            "when HTTP_REQUEST {",
            "    log local0. \"Request received\"",
            "    pool /Common/default_pool",
            "}"
        ]

        irule = IRuleStanza(
            prefix=("ltm", "rule"),
            name="/Common/simple_test",
            config_lines=lines
        )

        parsed = irule.parsed_config
        flow = parsed['irule_flow']

        # Both actions should be in flow with just the event context
        log_action = next((f for f in flow if 'log' in f), None)
        pool_action = next((f for f in flow if 'pool' in f), None)

        assert log_action is not None
        assert pool_action is not None
        assert log_action == 'when HTTP_REQUEST { -> log local0. "Request received"'
        assert pool_action == 'when HTTP_REQUEST { -> pool /Common/default_pool'

    def test_cache_invalidation_on_modification(self, simple_irule_content):
        """Test that cache is properly invalidated when iRule is modified"""
        irule = IRuleStanza(
            prefix=("ltm", "rule"),
            name="/Common/test",
            config_lines=simple_irule_content
        )

        # Parse initially
        initial_parsed = irule.parsed_config
        assert '/Common/api_pool' in initial_parsed['unique_words']

        # Modify the iRule
        new_lines = [
            "when HTTP_REQUEST {",
            "    pool /Common/new_pool",
            "}"
        ]
        irule.config_lines = new_lines

        # Cache should be invalidated
        assert irule._parsed_config is None

        # New parse should reflect changes
        new_parsed = irule.parsed_config
        assert '/Common/new_pool' in new_parsed['unique_words']
        assert '/Common/api_pool' not in new_parsed['unique_words']