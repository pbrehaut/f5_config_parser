import pytest
from f5_config_parser.stanza.partition_ip_rd_parser import extract_fields


class TestExtractFieldsValid:
    """Test extract_fields function with valid inputs"""

    def test_valid_inputs(self):
        """Test that valid inputs return correct field extractions"""

        test_cases = [
            # Basic cases with partition-1 and private IPs
            ("/partition-1/192.168.1.100%6:1050", {
                'partition': 'partition-1', 'ip_address': '192.168.1.100',
                'route_domain': '6', 'port': '1050'
            }),
            ("/partition-1/192.168.1.100:1050", {
                'partition': 'partition-1', 'ip_address': '192.168.1.100', 'port': '1050'
            }),
            ("192.168.1.100:1050", {
                'ip_address': '192.168.1.100', 'port': '1050'
            }),
            ("/partition-1/192.168.1.100%6:http", {
                'partition': 'partition-1', 'ip_address': '192.168.1.100',
                'route_domain': '6', 'service': 'http'
            }),
            ("/partition-1/192.168.1.100%621:http", {
                'partition': 'partition-1', 'ip_address': '192.168.1.100',
                'route_domain': '621', 'service': 'http'
            }),
            ("/partition-1/192.168.1.100%621:53", {
                'partition': 'partition-1', 'ip_address': '192.168.1.100',
                'route_domain': '621', 'port': '53'
            }),

            # Different partition name variations
            ("/partition_2/10.0.0.50%12:443", {
                'partition': 'partition_2', 'ip_address': '10.0.0.50',
                'route_domain': '12', 'port': '443'
            }),
            ("/partition_prod/172.16.0.25%3:80", {
                'partition': 'partition_prod', 'ip_address': '172.16.0.25',
                'route_domain': '3', 'port': '80'
            }),
            ("/partition-dev/192.168.100.10%1:22", {
                'partition': 'partition-dev', 'ip_address': '192.168.100.10',
                'route_domain': '1', 'port': '22'
            }),
            ("/partition123/10.1.1.1%45:8080", {
                'partition': 'partition123', 'ip_address': '10.1.1.1',
                'route_domain': '45', 'port': '8080'
            }),

            # Service name variations
            ("/partition-1/192.168.1.200%6:ssh", {
                'partition': 'partition-1', 'ip_address': '192.168.1.200',
                'route_domain': '6', 'service': 'ssh'
            }),
            ("/partition-1/10.0.0.100%12:ftp", {
                'partition': 'partition-1', 'ip_address': '10.0.0.100',
                'route_domain': '12', 'service': 'ftp'
            }),

            # Edge cases - missing optional components
            ("192.168.1.100%600:1050", {
                'ip_address': '192.168.1.100', 'route_domain': '600', 'port': '1050'
            }),
            ("/partition-1/192.168.1.100:8080", {
                'partition': 'partition-1', 'ip_address': '192.168.1.100', 'port': '8080'
            }),

            # Large numbers
            ("/partition-1/192.168.1.100%65535:65535", {
                'partition': 'partition-1', 'ip_address': '192.168.1.100',
                'route_domain': '65535', 'port': '65535'
            }),
        ]

        for input_string, expected_result in test_cases:
            result = extract_fields(input_string)
            assert result == expected_result, f"Failed for input: {input_string}"


class TestExtractFieldsExceptions:
    """Test extract_fields function with invalid inputs that should raise exceptions"""

    def test_missing_ip_address(self):
        """Test that missing IP address raises ValueError"""

        invalid_inputs = [
            "/partition-1/%6:1050",  # No IP
            "%600:1050",  # No IP
            ":1050",  # No IP
            "/partition-1/:8080",  # No IP
            "partition-1:443",  # No IP (not a valid IP format)
            "not.an.ip:80",  # Invalid IP format
        ]

        for input_string in invalid_inputs:
            with pytest.raises(ValueError, match=f"Required field 'ip_address' not found in input string: '{input_string}'"):
                extract_fields(input_string, required_fields=['ip_address', 'port'])

    def test_missing_port_and_service(self):
        """Test that missing both port and service raises ValueError"""

        invalid_inputs = [
            "/partition-1/192.168.1.100",  # No port or service
            "192.168.1.100%600",  # No port or service
            "192.168.1.100",  # Just IP
            "/partition-1/192.168.1.100%600",  # No port or service
            "/partition-1/10.0.0.50%100",  # No port or service
        ]

        for input_string in invalid_inputs:
            with pytest.raises(ValueError, match=f"Required field 'port' not found in input string: '{input_string}'"):
                extract_fields(input_string, required_fields=['ip_address', 'port'])

    def test_invalid_ip_formats(self):
        """Test that invalid IP formats raise ValueError"""

        invalid_inputs = [
            "/partition-1/192.168.1:80",  # Incomplete IP
        ]

        for input_string in invalid_inputs:
            with pytest.raises(ValueError, match=f"Required field 'ip_address' not found in input string: '{input_string}'"):
                extract_fields(input_string, required_fields=['ip_address', 'port'])