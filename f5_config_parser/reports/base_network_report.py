from f5_config_parser import load_collection_from_archive
from f5_config_parser.ucs import UCS
from f5_config_parser.collection import StanzaCollection
import pandas as pd
import os
from typing import Dict, List, Tuple, Union


def build_network_relationships(all_stanzas: StanzaCollection, device_name: str) -> Tuple[list[dict], list[dict]]:
    """
    Build consolidated network relationship tables linking routes, self IPs, VLANs, and interfaces.

    Args:
        all_stanzas: StanzaCollection containing all F5 configuration stanzas
        device_name: Name of the source device

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
            'source_device': device_name,
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

        # Base info with source device
        base_with_device = {'source_device': device_name, **vlan_info['base']}

        # Create rows for each interface in the VLAN
        if vlan_info['interfaces']:
            for interface_data in vlan_info['interfaces']:
                row = {**base_with_device, **interface_data}
                self_ips_table.append(row)
        else:
            # No interfaces found, create row with base info only
            row = {**base_with_device,
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
        }
        try:
            interface_info['tagged'] = interface_config.get('tagged', False)
            interface_info['tag_mode'] = interface_config.get('tag-mode', '')
        except AttributeError:
            interface_info['tagged'] = False
            interface_info['tag_mode'] = ''

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


def generate_network_report(
        input_files: Union[Tuple[str, str], List[Tuple[str, str]], str, List[str]],
        output_dir: str,
        input_type: str = 'archive',
        output_filename: str = None
) -> Dict[str, str]:
    """
    Generate network configuration report.

    Args:
        input_files: File path(s) to process:
            - For 'archive' type: Single tuple (config_file, tar_file) or
              list of tuples [(config1, tar1), (config2, tar2), ...]
            - For 'ucs' type: Single UCS file path (str) or
              list of UCS file paths [ucs1, ucs2, ...]
        output_dir: Base directory where reports will be saved
        input_type: Type of input files - 'archive' or 'ucs' (default: 'archive')
        output_filename: Optional filename for the Excel report.
                        If not provided, defaults to 'network_report.xlsx'

    Returns:
        Dictionary containing path to generated file:
        - 'excel': Path to Excel report
    """
    # Normalise input_files to a list
    file_list = []

    if input_type == 'archive':
        # Handle archive type input
        if isinstance(input_files, tuple) and len(input_files) == 2 and isinstance(input_files[0], str):
            # Single tuple (config, tar)
            file_list = [input_files]
        elif isinstance(input_files, list):
            # List of tuples
            file_list = input_files
        else:
            raise ValueError("For 'archive' type, input_files must be a tuple (config, tar) or list of tuples")

        # Validate files exist
        for config_file, tar_file in file_list:
            if not os.path.exists(config_file):
                raise FileNotFoundError(f"Configuration file not found: {config_file}")
            if not os.path.exists(tar_file):
                raise FileNotFoundError(f"Tar file not found: {tar_file}")

    elif input_type == 'ucs':
        # Handle UCS type input
        if isinstance(input_files, str):
            # Single UCS file
            file_list = [input_files]
        elif isinstance(input_files, list):
            # List of UCS files
            file_list = input_files
        else:
            raise ValueError("For 'ucs' type, input_files must be a string path or list of paths")

        # Validate files exist
        for ucs_file in file_list:
            if not os.path.exists(ucs_file):
                raise FileNotFoundError(f"UCS file not found: {ucs_file}")
    else:
        raise ValueError(f"Invalid input_type: {input_type}. Must be 'archive' or 'ucs'")

    # Determine filename
    if output_filename is None:
        filename = "network_report.xlsx"
    else:
        # Ensure .xlsx extension
        if not output_filename.endswith('.xlsx'):
            filename = f"{output_filename}.xlsx"
        else:
            filename = output_filename

    # Create subdirectory for network reports
    network_dir = os.path.join(output_dir, "network")
    os.makedirs(network_dir, exist_ok=True)

    # Lists to accumulate all routes and self IPs across devices
    all_routes = []
    all_self_ips = []

    # Process each file
    for file_info in file_list:
        # Load collection based on input type
        if input_type == 'archive':
            config_file, tar_file = file_info
            all_stanzas = load_collection_from_archive(config_path=config_file, archive_path=tar_file)
            # Fallback device name from config file
            fallback_device_name = os.path.splitext(os.path.basename(config_file))[0]
        else:  # ucs
            ucs_file = file_info
            with UCS(ucs_file) as ucs:
                all_stanzas = ucs.load_collection()
            # Fallback device name from UCS file
            fallback_device_name = os.path.splitext(os.path.basename(ucs_file))[0]

        # Try to extract device hostname from configuration
        device_name = fallback_device_name  # Default to filename
        self_device = all_stanzas.filter(('cm', 'device'), **{'self-device': 'true'})
        if self_device and len(self_device) == 1:
            hostname = self_device[0].parsed_config.get('hostname')
            if hostname:
                device_name = hostname.split('.')[0]

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
            print(f"Warning: No data found for filter {tuple_filters[0]} in {device_name}")

        for filter_tuple in tuple_filters[1:]:
            filtered_stanzas = all_stanzas.filter(filter_tuple)
            if filtered_stanzas:
                base_stanzas += filtered_stanzas
            else:
                print(f"Warning: No data found for filter {filter_tuple} in {device_name}")

        # Build network relationships for this device
        route_table, self_ip_table = build_network_relationships(base_stanzas.filter(('net',)), device_name)

        # Accumulate results
        all_routes.extend(route_table)
        all_self_ips.extend(self_ip_table)

    # Convert to DataFrames
    routes_df = pd.DataFrame(all_routes)
    self_ips_df = pd.DataFrame(all_self_ips)

    # Export to Excel with multiple sheets
    excel_file = os.path.join(network_dir, filename)
    with pd.ExcelWriter(excel_file, engine='openpyxl') as writer:
        if not routes_df.empty:
            routes_df.to_excel(writer, sheet_name='Routes', index=False)
        if not self_ips_df.empty:
            self_ips_df.to_excel(writer, sheet_name='Self IPs', index=False)

    print(f"Network report generated successfully!")
    print(f"Excel report: {excel_file}")

    return {
        'excel': excel_file
    }