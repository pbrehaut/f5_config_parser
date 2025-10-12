import pytest
from f5_config_parser.stanza import ConfigStanza, NodeStanza, PoolStanza, VirtualServerStanza, GenericStanza, \
    IRuleStanza


def test_stanza_ordering_by_full_path():
    """Test that stanzas are sorted with ltm virtual taking precedence, then alphabetically by full_path"""
    # Create instances with different full_path values
    stanzas = [
        PoolStanza(
            prefix=("ltm", "pool"),
            name="z-pool",
            config_lines=["members { 192.168.1.1:80 }"]
        ),
        VirtualServerStanza(
            prefix=("ltm", "virtual"),
            name="a-virtual",
            config_lines=["destination 192.168.1.100:80"]
        ),
        NodeStanza(
            prefix=("ltm", "node"),
            name="m-node",
            config_lines=["address 192.168.1.1"]
        ),
        IRuleStanza(
            prefix=("ltm", "rule"),
            name="b-rule",
            config_lines=["when HTTP_REQUEST { log local0. \"test\" }"]
        ),
        VirtualServerStanza(
            prefix=("ltm", "virtual"),
            name="z-virtual",
            config_lines=["destination 192.168.1.101:80"]
        )
    ]

    # Sort the list
    sorted_stanzas = sorted(stanzas)

    # Get the full_path values to verify ordering
    sorted_paths = [s.full_path for s in sorted_stanzas]

    # Verify ltm virtual items come first, then alphabetically sorted
    expected_paths = [
        "ltm virtual a-virtual",
        "ltm virtual z-virtual",
        "ltm node m-node",
        "ltm pool z-pool",
        "ltm rule b-rule"
    ]

    assert sorted_paths == expected_paths


def test_stanza_ordering_same_prefix_different_names():
    """Test that stanzas with the same prefix are sorted by name"""
    # Create multiple instances of same type with different names
    pools = [
        PoolStanza(
            prefix=("ltm", "pool"),
            name="z-pool",
            config_lines=["members { 192.168.1.1:80 }"]
        ),
        PoolStanza(
            prefix=("ltm", "pool"),
            name="a-pool",
            config_lines=["members { 192.168.1.2:80 }"]
        ),
        PoolStanza(
            prefix=("ltm", "pool"),
            name="m-pool",
            config_lines=["members { 192.168.1.3:80 }"]
        )
    ]

    # Sort the list
    sorted_pools = sorted(pools)

    # Verify they're sorted by full_path (which includes the name)
    expected_paths = ['ltm pool a-pool', 'ltm pool m-pool', 'ltm pool z-pool']
    actual_paths = [p.full_path for p in sorted_pools]

    assert actual_paths == expected_paths