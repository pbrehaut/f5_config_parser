from f5_config_parser import load_collection_from_archive
from f5_config_parser.ucs import UCS
from f5_config_parser.collection import StanzaCollection
import pandas as pd
import os
from typing import Dict, List, Tuple, Union


def build_system_tables(base_stanzas: StanzaCollection, device_name: str) -> dict[str, list[dict]]:
    """
    Build comprehensive system configuration tables from F5 stanzas.

    Args:
        base_stanzas: StanzaCollection containing system configuration stanzas
        device_name: Name of the source device

    Returns:
        Dictionary mapping sheet names to lists of row dictionaries
    """
    tables = {}

    # Device Information
    tables['Devices'] = _build_devices_table(base_stanzas, device_name)

    # High Availability
    tables['Device Groups'] = _build_device_groups_table(base_stanzas, device_name)
    tables['Device Group Members'] = _build_device_group_members_table(base_stanzas, device_name)
    tables['Traffic Groups'] = _build_traffic_groups_table(base_stanzas, device_name)
    tables['Trust Domains'] = _build_trust_domains_table(base_stanzas, device_name)

    # Management Network
    tables['Management Routes'] = _build_management_routes_table(base_stanzas, device_name)
    tables['Management DHCP'] = _build_management_dhcp_table(base_stanzas, device_name)

    # Services
    tables['DNS & NTP'] = _build_dns_ntp_table(base_stanzas, device_name)
    tables['HTTP Access'] = _build_http_access_table(base_stanzas, device_name)

    # SNMP
    tables['SNMP Communities'] = _build_snmp_communities_table(base_stanzas, device_name)
    tables['SNMP Disk Monitors'] = _build_snmp_disk_monitors_table(base_stanzas, device_name)
    tables['SNMP Process Monitors'] = _build_snmp_process_monitors_table(base_stanzas, device_name)

    # Syslog
    tables['Syslog Servers'] = _build_syslog_servers_table(base_stanzas, device_name)

    # Modules
    tables['Active Modules'] = _build_active_modules_table(base_stanzas, device_name)
    tables['Optional Modules'] = _build_optional_modules_table(base_stanzas, device_name)

    return tables


def _build_devices_table(stanzas: StanzaCollection, device_name: str) -> list[dict]:
    """Build device information table."""
    rows = []

    devices = stanzas.filter(('cm', 'device'))
    mgmt_ips = stanzas.filter(('sys', 'management-ip'))
    global_settings = stanzas.filter(prefix=('sys',), name='global-settings')

    # Get management IP (usually only one)
    mgmt_ip = None
    for stanza in mgmt_ips:
        mgmt_ip = stanza.name
        break

    # Get global settings
    hostname_global = None
    gui_setup = None
    for stanza in global_settings:
        hostname_global = stanza.parsed_config.get('hostname')
        gui_setup = stanza.parsed_config.get('gui-setup')
        break

    for device in devices:
        config = device.parsed_config
        row = {
            'source_device': device_name,
            'device_name': device.name,
            'hostname': config.get('hostname'),
            'management_ip': config.get('management-ip'),
            'configsync_ip': config.get('configsync-ip'),
            'product': config.get('product'),
            'version': config.get('version'),
            'build': config.get('build'),
            'edition': config.get('edition', '').strip('"'),
            'platform_id': config.get('platform-id'),
            'chassis_id': config.get('chassis-id', '').strip('"'),
            'base_mac': config.get('base-mac'),
            'marketing_name': config.get('marketing-name', '').strip('"'),
            'timezone': config.get('time-zone'),
            'self_device': config.get('self-device'),
            'global_hostname': hostname_global,
            'gui_setup': gui_setup,
            'management_ip_configured': mgmt_ip
        }
        rows.append(row)

    return rows


def _build_device_groups_table(stanzas: StanzaCollection, device_name: str) -> list[dict]:
    """Build device groups table."""
    rows = []

    device_groups = stanzas.filter(('cm', 'device-group'))

    for dg in device_groups:
        config = dg.parsed_config
        row = {
            'source_device': device_name,
            'device_group_name': dg.name,
            'type': config.get('type'),
            'auto_sync': config.get('auto-sync'),
            'network_failover': config.get('network-failover'),
            'hidden': config.get('hidden'),
            'device_count': len(config.get('devices', {}))
        }
        rows.append(row)

    return rows


def _build_device_group_members_table(stanzas: StanzaCollection, device_name: str) -> list[dict]:
    """Build device group members table (one row per member)."""
    rows = []

    device_groups = stanzas.filter(('cm', 'device-group'))

    for dg in device_groups:
        config = dg.parsed_config
        devices = config.get('devices', {})

        for device_member_name in devices.keys():
            row = {
                'source_device': device_name,
                'device_group_name': dg.name,
                'device_name': device_member_name
            }
            rows.append(row)

    return rows


def _build_traffic_groups_table(stanzas: StanzaCollection, device_name: str) -> list[dict]:
    """Build traffic groups table."""
    rows = []

    traffic_groups = stanzas.filter(('cm', 'traffic-group'))

    for tg in traffic_groups:
        config = tg.parsed_config
        row = {
            'source_device': device_name,
            'traffic_group_name': tg.name,
            'unit_id': config.get('unit-id')
        }
        rows.append(row)

    return rows


def _build_trust_domains_table(stanzas: StanzaCollection, device_name: str) -> list[dict]:
    """Build trust domains table."""
    rows = []

    trust_domains = stanzas.filter(('cm', 'trust-domain'))

    for td in trust_domains:
        config = td.parsed_config
        ca_devices = config.get('ca-devices', '')

        # Parse ca-devices string if it exists
        if isinstance(ca_devices, str):
            ca_devices = ca_devices.strip('{}').strip()

        row = {
            'source_device': device_name,
            'trust_domain_name': td.name,
            'ca_cert': config.get('ca-cert'),
            'ca_cert_bundle': config.get('ca-cert-bundle'),
            'ca_key': config.get('ca-key'),
            'ca_devices': ca_devices,
            'guid': config.get('guid'),
            'status': config.get('status'),
            'trust_group': config.get('trust-group')
        }
        rows.append(row)

    return rows


def _build_management_routes_table(stanzas: StanzaCollection, device_name: str) -> list[dict]:
    """Build management routes table."""
    rows = []

    mgmt_routes = stanzas.filter(('sys', 'management-route'))

    for route in mgmt_routes:
        config = route.parsed_config
        row = {
            'source_device': device_name,
            'route_name': route.name,
            'network': config.get('network'),
            'gateway': config.get('gateway'),
            'mtu': config.get('mtu'),
            'description': config.get('description')
        }
        rows.append(row)

    return rows


def _build_management_dhcp_table(stanzas: StanzaCollection, device_name: str) -> list[dict]:
    """Build management DHCP table."""
    rows = []

    mgmt_dhcp = stanzas.filter(('sys', 'management-dhcp'))

    for dhcp in mgmt_dhcp:
        config = dhcp.parsed_config
        request_options = config.get('request-options', '')

        # Parse request-options if it's a string with braces
        if isinstance(request_options, str):
            request_options = request_options.strip('{}').strip()

        row = {
            'source_device': device_name,
            'dhcp_name': dhcp.name,
            'request_options': request_options
        }
        rows.append(row)

    return rows


def _build_dns_ntp_table(stanzas: StanzaCollection, device_name: str) -> list[dict]:
    """Build DNS and NTP configuration table."""
    rows = []

    dns_stanzas = stanzas.filter(prefix=('sys',), name='dns')
    ntp_stanzas = stanzas.filter(prefix=('sys',), name='ntp')

    # Get DNS info
    dns_servers = None
    for stanza in dns_stanzas:
        config = stanza.parsed_config
        servers = config.get('name-servers', '')
        if isinstance(servers, str):
            dns_servers = servers.strip('{}').strip()
        elif isinstance(servers, list):
            dns_servers = ', '.join(servers)
        break

    # Get NTP info
    ntp_servers = None
    ntp_timezone = None
    for stanza in ntp_stanzas:
        config = stanza.parsed_config
        servers = config.get('servers', '')
        if isinstance(servers, str):
            ntp_servers = servers.strip('{}').strip()
        elif isinstance(servers, list):
            ntp_servers = ', '.join(servers)
        ntp_timezone = config.get('timezone')
        break

    row = {
        'source_device': device_name,
        'dns_servers': dns_servers,
        'ntp_servers': ntp_servers,
        'ntp_timezone': ntp_timezone
    }
    rows.append(row)

    return rows


def _build_http_access_table(stanzas: StanzaCollection, device_name: str) -> list[dict]:
    """Build HTTP access configuration table."""
    rows = []

    httpd_stanzas = stanzas.filter(prefix=('sys',), name='httpd')

    for stanza in httpd_stanzas:
        config = stanza.parsed_config
        allow = config.get('allow', '')

        # Parse allow if it's a string with braces
        if isinstance(allow, str):
            allow = allow.strip('{}').strip()
        elif isinstance(allow, list):
            allow = ', '.join(allow)

        row = {
            'source_device': device_name,
            'allowed_addresses': allow,
            'include': config.get('include')
        }
        rows.append(row)

    return rows


def _build_snmp_communities_table(stanzas: StanzaCollection, device_name: str) -> list[dict]:
    """Build SNMP communities table."""
    rows = []

    snmp_stanzas = stanzas.filter(prefix=('sys',), name='snmp')

    for stanza in snmp_stanzas:
        config = stanza.parsed_config
        communities = config.get('communities', {})

        for comm_name, comm_config in communities.items():
            row = {
                'source_device': device_name,
                'community_path': comm_name,
                'community_name': comm_config.get('community-name'),
                'source': comm_config.get('source')
            }
            rows.append(row)

    return rows


def _build_snmp_disk_monitors_table(stanzas: StanzaCollection, device_name: str) -> list[dict]:
    """Build SNMP disk monitors table."""
    rows = []

    snmp_stanzas = stanzas.filter(prefix=('sys',), name='snmp')

    for stanza in snmp_stanzas:
        config = stanza.parsed_config
        disk_monitors = config.get('disk-monitors', {})

        for monitor_name, monitor_config in disk_monitors.items():
            row = {
                'source_device': device_name,
                'monitor_name': monitor_name,
                'path': monitor_config.get('path'),
                'minspace': monitor_config.get('minspace')
            }
            rows.append(row)

    return rows


def _build_snmp_process_monitors_table(stanzas: StanzaCollection, device_name: str) -> list[dict]:
    """Build SNMP process monitors table."""
    rows = []

    snmp_stanzas = stanzas.filter(prefix=('sys',), name='snmp')

    for stanza in snmp_stanzas:
        config = stanza.parsed_config
        process_monitors = config.get('process-monitors', {})

        for monitor_name, monitor_config in process_monitors.items():
            row = {
                'source_device': device_name,
                'monitor_name': monitor_name,
                'process': monitor_config.get('process'),
                'max_processes': monitor_config.get('max-processes')
            }
            rows.append(row)

    return rows


def _build_syslog_servers_table(stanzas: StanzaCollection, device_name: str) -> list[dict]:
    """Build syslog servers table."""
    rows = []

    syslog_stanzas = stanzas.filter(prefix=('sys',), name='syslog')

    for stanza in syslog_stanzas:
        config = stanza.parsed_config
        remote_servers = config.get('remote-servers', {})

        for server_name, server_config in remote_servers.items():
            row = {
                'source_device': device_name,
                'server_name': server_name,
                'host': server_config.get('host')
            }
            rows.append(row)

        # Also capture the include configuration if present
        if config.get('include'):
            row = {
                'source_device': device_name,
                'server_name': 'include_config',
                'host': config.get('include')
            }
            rows.append(row)

    return rows


def _build_active_modules_table(stanzas: StanzaCollection, device_name: str) -> list[dict]:
    """Build active modules table (one row per module)."""
    rows = []

    devices = stanzas.filter(('cm', 'device'))

    for device in devices:
        config = device.parsed_config
        modules_str = config.get('active-modules', '')

        # Parse modules string
        modules = _parse_modules_string(modules_str)

        for module in modules:
            row = {
                'source_device': device_name,
                'device_name': device.name,
                'module': module
            }
            rows.append(row)

    return rows


def _build_optional_modules_table(stanzas: StanzaCollection, device_name: str) -> list[dict]:
    """Build optional modules table (one row per module)."""
    rows = []

    devices = stanzas.filter(('cm', 'device'))

    for device in devices:
        config = device.parsed_config
        modules_str = config.get('optional-modules', '')

        # Parse modules string
        modules = _parse_modules_string(modules_str)

        for module in modules:
            row = {
                'source_device': device_name,
                'device_name': device.name,
                'module': module
            }
            rows.append(row)

    return rows


def _parse_modules_string(modules_str: str) -> list[str]:
    """Parse modules string into individual module names."""
    if not modules_str:
        return []

    # Remove outer braces and split by quoted strings
    modules_str = modules_str.strip('{}').strip()

    modules = []
    current_module = []
    in_quotes = False

    for char in modules_str:
        if char == '"':
            in_quotes = not in_quotes
            if not in_quotes and current_module:
                # End of a module
                modules.append(''.join(current_module).strip())
                current_module = []
        elif in_quotes:
            current_module.append(char)

    # Handle any remaining module
    if current_module:
        modules.append(''.join(current_module).strip())

    return [m for m in modules if m]


def generate_device_report(
        input_files: Union[Tuple[str, str], List[Tuple[str, str]], str, List[str]],
        output_dir: str,
        input_type: str = 'archive',
        output_filename: str = None
) -> Dict[str, str]:
    """
    Generate device and system configuration report.

    Args:
        input_files: File path(s) to process:
            - For 'archive' type: Single tuple (config_file, tar_file) or
              list of tuples [(config1, tar1), (config2, tar2), ...]
            - For 'ucs' type: Single UCS file path (str) or
              list of UCS file paths [ucs1, ucs2, ...]
        output_dir: Base directory where reports will be saved
        input_type: Type of input files - 'archive' or 'ucs' (default: 'archive')
        output_filename: Optional filename for the Excel report.
                        If not provided, defaults to 'system_report.xlsx'

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
        filename = "system_report.xlsx"
    else:
        # Ensure .xlsx extension
        if not output_filename.endswith('.xlsx'):
            filename = f"{output_filename}.xlsx"
        else:
            filename = output_filename

    # Create subdirectory for device reports
    device_dir = os.path.join(output_dir, "devices")
    os.makedirs(device_dir, exist_ok=True)

    # Dictionary to accumulate all tables across devices
    all_tables = {}

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

        all_stanzas.save_dependency_cache()

        # Try to extract device hostname from configuration
        device_name = fallback_device_name  # Default to filename
        self_device = all_stanzas.filter(('cm', 'device'), **{'self-device': 'true'})
        if self_device and len(self_device) == 1:
            hostname = self_device[0].parsed_config.get('hostname')
            if hostname:
                device_name = hostname.split('.')[0]

        # Filters using tuple syntax
        tuple_filters = (
            # High Availability & Clustering
            ('cm', 'device-group'),
            ('cm', 'device'),
            ('cm', 'traffic-group'),
            ('cm', 'trust-domain'),
            ('sys', 'ha-group'),
            ('sys', 'management-ip'),
            ('sys', 'management-route'),
            ('sys', 'management-dhcp')
        )

        # Filters using prefix and name syntax
        prefix_name_filters = (
            # Management & Access
            {'prefix': ('sys',), 'name': 'httpd'},
            {'prefix': ('sys',), 'name': 'sshd'},
            {'prefix': ('sys',), 'name': 'global-settings'},

            # Monitoring & Logging
            {'prefix': ('sys',), 'name': 'snmp'},
            {'prefix': ('sys',), 'name': 'syslog'},
            {'prefix': ('sys',), 'name': 'ntp'},

            # DNS
            {'prefix': ('sys',), 'name': 'dns'},
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

        for filter_dict in prefix_name_filters:
            filtered_stanzas = all_stanzas.filter(**filter_dict)
            if filtered_stanzas:
                base_stanzas += filtered_stanzas
            else:
                print(f"Warning: No data found for filter {filter_dict} in {device_name}")

        # Build system tables for this device
        device_tables = build_system_tables(base_stanzas, device_name)

        # Merge tables from this device into accumulated tables
        for sheet_name, table_data in device_tables.items():
            if sheet_name not in all_tables:
                all_tables[sheet_name] = []
            all_tables[sheet_name].extend(table_data)

    # Export consolidated tables to Excel
    excel_file = os.path.join(device_dir, filename)
    with pd.ExcelWriter(excel_file, engine='openpyxl') as writer:
        for sheet_name, table_data in all_tables.items():
            if table_data:  # Only write non-empty tables
                df = pd.DataFrame(table_data)
                df.to_excel(writer, sheet_name=sheet_name, index=False)

    print(f"Device report generated successfully!")
    print(f"Excel report: {excel_file}")

    return {
        'excel': excel_file
    }