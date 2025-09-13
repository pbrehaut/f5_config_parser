import pytest
from f5_config_parser.stanza import VirtualServerStanza


def test_virtual_server_str_simple():
    """Test __str__ output for a simple virtual server"""
    prefix = ("ltm", "virtual")
    name = "my-vs"
    config_lines = [
        "    destination 192.168.1.100:80",
        "    pool my-pool"
    ]

    vs = VirtualServerStanza(prefix, name, config_lines)

    expected = "ltm virtual my-vs {\n    destination 192.168.1.100:80\n    pool my-pool\n}\n"
    assert str(vs) == expected


def test_virtual_server_str_with_profiles():
    """Test __str__ output for virtual server with profiles"""
    prefix = ("ltm", "virtual")
    name = "web-vs"
    config_lines = [
        "    destination 10.0.1.50:443",
        "    pool web-pool",
        "    profiles {",
        "        http { }",
        "        ssl-client {",
        "            cert mycert",
        "            key mykey",
        "        }",
        "    }"
    ]

    vs = VirtualServerStanza(prefix, name, config_lines)

    expected = ("ltm virtual web-vs {\n"
                "    destination 10.0.1.50:443\n"
                "    pool web-pool\n"
                "    profiles {\n"
                "        http { }\n"
                "        ssl-client {\n"
                "            cert mycert\n"
                "            key mykey\n"
                "        }\n"
                "    }\n"
                "}\n")

    assert str(vs) == expected


def test_virtual_server_str_with_rules():
    """Test __str__ output for virtual server with iRules"""
    prefix = ("ltm", "virtual")
    name = "app-vs"
    config_lines = [
        "    destination 172.16.1.10:80",
        "    pool app-pool",
        "    rules {",
        "        redirect-rule",
        "        security-rule",
        "    }"
    ]

    vs = VirtualServerStanza(prefix, name, config_lines)

    expected = ("ltm virtual app-vs {\n"
                "    destination 172.16.1.10:80\n"
                "    pool app-pool\n"
                "    rules {\n"
                "        redirect-rule\n"
                "        security-rule\n"
                "    }\n"
                "}\n")

    assert str(vs) == expected


def test_multiple_virtual_servers_concatenation():
    """Test that multiple virtual servers print without blank lines between them"""
    vs1 = VirtualServerStanza(("ltm", "virtual"), "vs1", ["    destination 1.1.1.1:80"])
    vs2 = VirtualServerStanza(("ltm", "virtual"), "vs2", ["    destination 2.2.2.2:80"])

    combined_output = str(vs1) + str(vs2)

    expected = ("ltm virtual vs1 {\n"
                "    destination 1.1.1.1:80\n"
                "}\n"
                "ltm virtual vs2 {\n"
                "    destination 2.2.2.2:80\n"
                "}\n")

    assert combined_output == expected


if __name__ == "__main__":
    # Sample data test
    vs1 = VirtualServerStanza(("ltm", "virtual"), "test-vs", ["    destination 192.168.1.100:80", "    pool test-pool"])
    vs2 = VirtualServerStanza(("ltm", "virtual"), "secure-vs",
                              ["    destination 10.0.1.50:443", "    profiles {", "        ssl { }", "    }"])

    print(str(vs1) + str(vs2))
    pass