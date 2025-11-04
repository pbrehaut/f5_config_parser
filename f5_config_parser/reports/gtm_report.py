from f5_config_parser import load_collection_from_archive
from f5_config_parser.ucs import UCS
from f5_config_parser.collection import StanzaCollection
import pandas as pd
import os
from typing import Dict, List, Tuple, Union


def build_gtm_server_table(all_stanzas: StanzaCollection, device_name: str) -> list[dict]:
    """
    Build GTM server table with server names, IPs, and type (GTM/LTM).

    Args:
        all_stanzas: StanzaCollection containing all F5 configuration stanzas
        device_name: Name of the source device

    Returns:
        List of dictionaries containing server information
    """
    server_table = []

    # Get all GTM servers
    gtm_servers = all_stanzas.filter(('gtm', 'server'))

    for server in gtm_servers:
        # Determine if it's GTM or LTM based on virtual-servers presence
        has_virtual_servers = 'virtual-servers' in server.parsed_config
        server_type = 'LTM' if has_virtual_servers else 'GTM'

        # Extract devices and their IPs
        devices = server.parsed_config.get('devices', {})

        for device_name_inner, device_config in devices.items():
            addresses = device_config.get('addresses', {})

            for ip_address in addresses.keys():
                row = {
                    'source_device': device_name,
                    'server_name': server.name,
                    'ip_address': ip_address,
                    'server_type': server_type,
                }
                server_table.append(row)

    return server_table


def build_gtm_virtual_servers_table(all_stanzas: StanzaCollection, device_name: str) -> list[dict]:
    """
    Build GTM virtual servers table with server name, virtual server name, and destination.

    Args:
        all_stanzas: StanzaCollection containing all F5 configuration stanzas
        device_name: Name of the source device

    Returns:
        List of dictionaries containing virtual server information
    """
    virtual_servers_table = []

    # Get all GTM servers
    gtm_servers = all_stanzas.filter(('gtm', 'server'))

    for server in gtm_servers:
        # Get virtual servers if they exist
        virtual_servers = server.parsed_config.get('virtual-servers', {})

        for vs_name, vs_config in virtual_servers.items():
            destination = vs_config.get('destination', '')

            row = {
                'source_device': device_name,
                'gtm_server_name': server.name,
                'virtual_server_name': vs_name,
                'destination': destination,
            }
            virtual_servers_table.append(row)

    return virtual_servers_table


def preprocess_wideip_relationships(all_stanzas: StanzaCollection, device_name: str) -> list[dict]:
    """
    Preprocess Wide IP relationships by gathering pools, servers, and virtual servers.

    Args:
        all_stanzas: StanzaCollection containing all F5 configuration stanzas
        device_name: Name of the source device

    Returns:
        List of dictionaries containing preprocessed Wide IP relationship data
    """
    wideip_data = []

    # Get all Wide IP A records
    wideip_stanzas = all_stanzas.filter(('gtm', 'wideip', 'a'))

    for wideip in wideip_stanzas:
        # Get related stanzas for this Wide IP
        related_stanzas = all_stanzas.get_related_stanzas([wideip])

        # Find pool stanzas in the related stanzas
        pool_stanzas = [s for s in related_stanzas if s.prefix == ('gtm', 'pool', 'a')]

        # Build relationship data for each pool
        for pool in pool_stanzas:
            # Get dependency map for this pool
            dependency_map = pool.get_dependency_map(related_stanzas)

            # Extract pool members
            pool_members = pool.parsed_config.get('members', {})

            # Process each pool member
            for member_key, member_config in pool_members.items():
                # Member key format: server_name:virtual_server_name
                if ':' in member_key:
                    server_name, vs_name = member_key.split(':', 1)
                else:
                    server_name = member_key
                    vs_name = None

                # Find the corresponding server stanza to get virtual server destination
                vs_destination = None
                for server_stanza in related_stanzas:
                    if server_stanza.prefix == ('gtm', 'server') and server_stanza.name == server_name:
                        virtual_servers = server_stanza.parsed_config.get('virtual-servers', {})
                        if vs_name and vs_name in virtual_servers:
                            vs_destination = virtual_servers[vs_name].get('destination', '')
                        break

                # Store the relationship data
                relationship = {
                    'source_device': device_name,
                    'wideip_name': wideip.name,
                    'pool_name': pool.name,
                    'load_balancing_mode': pool.parsed_config.get('load-balancing-mode', ''),
                    'member_order': member_config.get('member-order', ''),
                    'server_name': server_name,
                    'virtual_server_name': vs_name,
                    'virtual_server_destination': vs_destination,
                    'dependency_map': str(dependency_map),
                }
                wideip_data.append(relationship)

    return wideip_data


def generate_gtm_report(
        input_files: Union[Tuple[str, str], List[Tuple[str, str]], str, List[str]],
        output_dir: str,
        input_type: str = 'archive',
        output_filename: str = None
) -> Dict[str, str]:
    """
    Generate GTM configuration report.

    Args:
        input_files: File path(s) to process:
            - For 'archive' type: Single tuple (config_file, tar_file) or
              list of tuples [(config1, tar1), (config2, tar2), ...]
            - For 'ucs' type: Single UCS file path (str) or
              list of UCS file paths [ucs1, ucs2, ...]
        output_dir: Base directory where reports will be saved
        input_type: Type of input files - 'archive' or 'ucs' (default: 'archive')
        output_filename: Optional filename for the Excel report.
                        If not provided, defaults to 'gtm_report.xlsx'

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
        filename = "gtm_report.xlsx"
    else:
        # Ensure .xlsx extension
        if not output_filename.endswith('.xlsx'):
            filename = f"{output_filename}.xlsx"
        else:
            filename = output_filename

    # Create subdirectory for GTM reports
    gtm_dir = os.path.join(output_dir, "gtm")
    os.makedirs(gtm_dir, exist_ok=True)

    # Lists to accumulate all data across devices
    all_servers = []
    all_virtual_servers = []
    all_wideip_relationships = []

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

        # Build GTM tables for this device
        server_table = build_gtm_server_table(all_stanzas, device_name)
        virtual_servers_table = build_gtm_virtual_servers_table(all_stanzas, device_name)
        wideip_relationships = preprocess_wideip_relationships(all_stanzas, device_name)

        # Accumulate results
        all_servers.extend(server_table)
        all_virtual_servers.extend(virtual_servers_table)
        all_wideip_relationships.extend(wideip_relationships)

    # Convert to DataFrames
    servers_df = pd.DataFrame(all_servers)
    virtual_servers_df = pd.DataFrame(all_virtual_servers)
    wideip_relationships_df = pd.DataFrame(all_wideip_relationships)

    # Export to Excel
    excel_file = os.path.join(gtm_dir, filename)
    with pd.ExcelWriter(excel_file, engine='openpyxl') as writer:
        if not servers_df.empty:
            servers_df.to_excel(writer, sheet_name='GTM Servers', index=False)
        if not virtual_servers_df.empty:
            virtual_servers_df.to_excel(writer, sheet_name='Virtual Servers', index=False)
        if not wideip_relationships_df.empty:
            wideip_relationships_df.to_excel(writer, sheet_name='Wide IP Relationships', index=False)

    print(f"GTM report generated successfully!")
    print(f"Excel report: {excel_file}")

    return {
        'excel': excel_file
    }