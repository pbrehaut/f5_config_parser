from f5_config_parser.collection import StanzaCollection
import pandas as pd


def build_network_relationships(all_stanzas: StanzaCollection) -> tuple[list[dict], list[dict]]:
    """
    Build consolidated network relationship tables linking routes, self IPs, VLANs, and interfaces.

    Args:
        all_stanzas: StanzaCollection containing all F5 configuration stanzas

    Returns:
        Tuple of (routes_table, self_ips_table) where each is a list of dictionaries
    """
    routes_table = []
    self_ips_table = []

    # Get all routes and self IPs
    route_stanzas = all_stanzas.filter(('net', 'route'))
    self_ip_stanzas = all_stanzas.filter(('net', 'self'))

    # Process routes
    for route in route_stanzas:
        related = all_stanzas.get_related_stanzas([route])

        # Extract route information
        route_info = {
            'route_name': route.name,
            'network': route.parsed_config.get('network', ''),
            'gateway': route.parsed_config.get('gw', ''),
            'route_domain': route.network_rd[1] if hasattr(route, 'network_rd') else '',
        }

        # Find self IP in related stanzas
        self_ip = None
        for stanza in related:
            if stanza.prefix == ('net', 'self'):
                self_ip = stanza
                break

        if self_ip:
            # Extract self IP and VLAN information
            vlan_info = _extract_vlan_info(self_ip, related, all_stanzas)

            # Create rows for each interface in the VLAN
            if vlan_info['interfaces']:
                for interface_data in vlan_info['interfaces']:
                    row = {**route_info, **vlan_info['base'], **interface_data}
                    routes_table.append(row)
            else:
                # No interfaces found, create row with base info only
                row = {**route_info, **vlan_info['base'],
                       'trunk_or_interface': None, 'is_trunk': None, 'tagged': None,
                       'tag_mode': None, 'physical_interfaces': None, 'lacp_enabled': None}
                routes_table.append(row)
        else:
            # Route with no self IP dependency
            row = {**route_info,
                   'self_ip': None, 'self_ip_name': None, 'traffic_group': None,
                   'vlan_name': None, 'vlan_tag': None,
                   'trunk_or_interface': None, 'is_trunk': None, 'tagged': None,
                   'tag_mode': None, 'physical_interfaces': None, 'lacp_enabled': None}
            routes_table.append(row)

    # Process all self IPs
    for self_ip in self_ip_stanzas:
        related = all_stanzas.get_related_stanzas([self_ip])

        # Extract self IP and VLAN information
        vlan_info = _extract_vlan_info(self_ip, related, all_stanzas)

        # Create rows for each interface in the VLAN
        if vlan_info['interfaces']:
            for interface_data in vlan_info['interfaces']:
                row = {**vlan_info['base'], **interface_data}
                self_ips_table.append(row)
        else:
            # No interfaces found, create row with base info only
            row = {**vlan_info['base'],
                   'trunk_or_interface': None, 'is_trunk': None, 'tagged': None,
                   'tag_mode': None, 'physical_interfaces': None, 'lacp_enabled': None}
            self_ips_table.append(row)

    return routes_table, self_ips_table


def _extract_vlan_info(self_ip, related_stanzas, all_stanzas) -> dict:
    """
    Extract VLAN and interface information for a self IP.

    Returns:
        Dictionary with 'base' (self IP and VLAN info) and 'interfaces' (list of interface details)
    """
    base_info = {
        'self_ip': self_ip.parsed_config.get('address', ''),
        'self_ip_name': self_ip.name,
        'traffic_group': self_ip.parsed_config.get('traffic-group', ''),
    }

    # Find VLAN in related stanzas
    vlan = None
    for stanza in related_stanzas:
        if stanza.prefix == ('net', 'vlan'):
            vlan = stanza
            break

    if not vlan:
        base_info.update({'vlan_name': None, 'vlan_tag': None})
        return {'base': base_info, 'interfaces': []}

    base_info.update({
        'vlan_name': vlan.name,
        'vlan_tag': vlan.parsed_config.get('tag', ''),
    })

    # Extract interface information
    interfaces_list = []
    vlan_interfaces = vlan.parsed_config.get('interfaces', {})

    for interface_name, interface_config in vlan_interfaces.items():
        interface_info = {
            'trunk_or_interface': interface_name,
            'tagged': interface_config.get('tagged', False),
            'tag_mode': interface_config.get('tag-mode', ''),
        }

        # Check if this interface is a trunk
        trunk = None
        for stanza in related_stanzas:
            if stanza.prefix == ('net', 'trunk') and stanza.name == interface_name:
                trunk = stanza
                break

        if trunk:
            interface_info['is_trunk'] = True
            # Get physical interfaces from trunk
            trunk_interfaces = trunk.parsed_config.get('interfaces', {})
            interface_info['physical_interfaces'] = ', '.join(sorted(trunk_interfaces.keys()))
            interface_info['lacp_enabled'] = trunk.parsed_config.get('lacp') == 'enabled'
        else:
            interface_info['is_trunk'] = False
            interface_info['physical_interfaces'] = None
            interface_info['lacp_enabled'] = None

        interfaces_list.append(interface_info)

    return {'base': base_info, 'interfaces': interfaces_list}


def generate_base_network_report(input_file: str):
    # Load configuration
    with open(input_file) as f:
        all_stanzas = StanzaCollection.from_config(f.read())

    # Filters using tuple syntax
    tuple_filters = (
        # Core Network Infrastructure
        ('net', 'self'),
        ('net', 'vlan'),
        ('net', 'route'),
        ('net', 'route-domain'),
        ('net', 'interface'),
        ('net', 'trunk'),

    )

    base_stanzas = all_stanzas.filter(tuple_filters[0])
    if not base_stanzas:
        print(f"Warning: No data found for filter {tuple_filters[0]}")

    for filter_tuple in tuple_filters[1:]:
        filtered_stanzas = all_stanzas.filter(filter_tuple)
        if filtered_stanzas:
            base_stanzas += filtered_stanzas
        else:
            print(f"Warning: No data found for filter {filter_tuple}")

    route_table, self_ip_table = build_network_relationships(base_stanzas.filter(('net',)))

    # Convert to DataFrames
    routes_df = pd.DataFrame(route_table)
    self_ips_df = pd.DataFrame(self_ip_table)

    # Export to Excel with multiple sheets
    output_file = 'f5_network_report.xlsx'
    with pd.ExcelWriter(output_file, engine='openpyxl') as writer:
        routes_df.to_excel(writer, sheet_name='Routes', index=False)
        self_ips_df.to_excel(writer, sheet_name='Self IPs', index=False)

    print(f"Report saved to {output_file}")