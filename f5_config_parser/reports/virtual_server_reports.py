from f5_config_parser import load_collection_from_archive
from f5_config_parser.ucs import UCS
from f5_config_parser.reports.collection_to_html import collection_to_html
import pandas as pd
import os
import shutil
from typing import Dict, List, Tuple, Union


def generate_virtual_server_report(
        input_files: Union[Tuple[str, str], List[Tuple[str, str]], str, List[str]],
        output_dir: str,
        input_type: str = 'archive',
        output_filename: str = None
) -> Dict[str, str]:
    """
    Generate virtual server report with network dependencies.

    Args:
        input_files: File path(s) to process:
            - For 'archive' type: Single tuple (config_file, tar_file) or
              list of tuples [(config1, tar1), (config2, tar2), ...]
            - For 'ucs' type: Single UCS file path (str) or
              list of UCS file paths [ucs1, ucs2, ...]
        output_dir: Base directory where reports will be saved
        input_type: Type of input files - 'archive' or 'ucs' (default: 'archive')
        output_filename: Optional base filename for reports (without extension).
                        If not provided, defaults to 'virtual_server_report'

    Returns:
        Dictionary containing paths to generated files:
        - 'html': Path to HTML report
        - 'excel': Path to Excel report
        - 'config_dir': Path to directory containing config files
        - 'zip': Path to zip file containing all reports
    """
    # Normalise input_files to a list of tuples with (file_identifier, file_info)
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

    # Determine base filename
    if output_filename is None:
        base_filename = "virtual_server_report"
    else:
        # Strip any extension from the provided filename
        base_filename = os.path.splitext(output_filename)[0]

    # Create subdirectory for virtual server reports
    vs_dir = os.path.join(output_dir, "virtual_servers")
    config_dir = os.path.join(vs_dir, "configs")
    os.makedirs(vs_dir, exist_ok=True)
    os.makedirs(config_dir, exist_ok=True)

    # List to store report rows
    report_data = []

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

        # Process virtual servers for this device
        for vs in all_stanzas.filter(('ltm', 'virtual')):
            vs_all = all_stanzas.get_related_stanzas([vs])

            # Extract network dependencies from virtual server
            vs_dependencies = vs.get_dependencies()
            vs_network_deps = []
            for dep_path in vs_dependencies:
                if dep_path in all_stanzas:
                    dep_obj = all_stanzas[dep_path]
                    if dep_obj.prefix == ('net', 'self') or dep_obj.prefix == ('net', 'route'):
                        vs_network_deps.append(dep_obj)

            # Extract VLAN names from virtual server network dependencies
            vs_vlans = set()
            has_self_ip = any(net_obj.prefix == ('net', 'self') for net_obj in vs_network_deps)

            for net_obj in vs_network_deps:
                if net_obj.prefix == ('net', 'self'):
                    vlan = net_obj.parsed_config.get('vlan')
                    if vlan:
                        vs_vlans.add(vlan)
                elif not has_self_ip and net_obj.prefix == ('net', 'route'):
                    # No self IP found, check route's dependencies for self IP
                    route_deps = net_obj.get_dependencies(collection=vs_all)
                    for route_dep_path in route_deps:
                        if route_dep_path in vs_all:
                            route_dep_obj = vs_all[route_dep_path]
                            if route_dep_obj.prefix == ('net', 'self'):
                                vlan = route_dep_obj.parsed_config.get('vlan')
                                if vlan:
                                    vs_vlans.add(vlan)

            # Extract pool members with their network dependencies
            pools = vs_all.filter(('ltm', 'pool'))
            pool_members = []
            for pool in pools:
                dep_map = pool.get_dependency_map(collection=vs_all)

                members = pool.parsed_config.get('members', {})
                for member_name, member_config in members.items():
                    ip_address = member_config.get('address', '')

                    # Get network dependencies for this specific member from the dependency map
                    member_key = ("members", member_name)
                    member_deps = dep_map.get(member_key, [])

                    # Check if member has self IP in dependencies
                    member_network_deps = []
                    for dep_path in member_deps:
                        if dep_path in vs_all:
                            dep_obj = vs_all[dep_path]
                            if dep_obj.prefix == ('net', 'self') or dep_obj.prefix == ('net', 'route'):
                                member_network_deps.append(dep_obj)

                    has_member_self_ip = any(dep.prefix == ('net', 'self') for dep in member_network_deps)

                    # Extract VLANs from member network dependencies
                    member_vlans = set()
                    for dep_obj in member_network_deps:
                        if dep_obj.prefix == ('net', 'self'):
                            vlan = dep_obj.parsed_config.get('vlan')
                            if vlan:
                                member_vlans.add(vlan)
                        elif not has_member_self_ip and dep_obj.prefix == ('net', 'route'):
                            # No self IP found for this member, check route's dependencies
                            route_deps = dep_obj.get_dependencies(collection=vs_all)
                            for route_dep_path in route_deps:
                                if route_dep_path in vs_all:
                                    route_dep_obj = vs_all[route_dep_path]
                                    if route_dep_obj.prefix == ('net', 'self'):
                                        vlan = route_dep_obj.parsed_config.get('vlan')
                                        if vlan:
                                            member_vlans.add(vlan)

                    # Store member with its VLANs
                    pool_members.append({
                        'name': member_name,
                        'ip': ip_address,
                        'vlans': ', '.join(sorted(member_vlans)) if member_vlans else ''
                    })

            # Extract certificate CNs
            certificates = [x for x in vs_all.filter(('certificate', 'object')) if x.is_ca == False]
            cert_cns = []
            for cert in certificates:
                subject = cert.subject
                if subject:
                    parts = subject.split(',')
                    for part in parts:
                        part = part.strip()
                        if part.startswith('CN='):
                            cn = part[3:]
                            cert_cns.append(cn)
                            break

            # Create a safe filename from the device name and virtual server name
            safe_device_name = device_name.replace('/', '_').replace('\\', '_')
            safe_vs_name = vs.name.replace('/', '_').replace('\\', '_')
            config_filename = f"{safe_device_name}_{safe_vs_name}.html"
            config_filepath = os.path.join(config_dir, config_filename)

            # Generate and write HTML configuration
            html_config = collection_to_html(vs_all)
            with open(config_filepath, 'w', encoding='utf-8') as f:
                f.write(html_config)

            # Determine maximum number of rows needed
            max_rows = max(len(pool_members), len(cert_cns), len(vs_vlans), 1)

            # Convert sets to sorted lists for indexing
            vs_vlans_list = sorted(vs_vlans)

            # Create rows
            for i in range(max_rows):
                row = {
                    'Source Device': device_name if i == 0 else '',
                    'Virtual Server Name': vs.name if i == 0 else '',
                    'Virtual Server Destination': vs.parsed_config.get('destination', '') if i == 0 else '',
                    'Virtual Server VLAN': vs_vlans_list[i] if i < len(vs_vlans_list) else '',
                    'Pool Member Name': pool_members[i]['name'] if i < len(pool_members) else '',
                    'Pool Member IP': pool_members[i]['ip'] if i < len(pool_members) else '',
                    'Pool Member VLAN': pool_members[i]['vlans'] if i < len(pool_members) else '',
                    'Certificate CN': cert_cns[i] if i < len(cert_cns) else '',
                    'Config Link': f'configs/{config_filename}' if i == 0 else ''
                }

                report_data.append(row)

    # Export to Excel
    df = pd.DataFrame(report_data)
    excel_file = os.path.join(vs_dir, f"{base_filename}.xlsx")
    df.to_excel(excel_file, index=False)

    # Generate HTML table with hyperlinks
    html_content = """
<!DOCTYPE html>
<html>
<head>
    <title>Virtual Server Report</title>
    <style>
        body {
            font-size: 12px;
        }
        table {
            border-collapse: collapse;
            width: 100%;
            font-family: Arial, sans-serif;
            font-size: 11px;
        }
        th, td {
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
        }
        th {
            background-color: #4CAF50;
            color: white;
        }
        tr:nth-child(even) {
            background-color: #f2f2f2;
        }
        a {
            color: #0066cc;
            text-decoration: none;
        }
        a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <h1>Virtual Server Report</h1>
    <table>
        <thead>
            <tr>
                <th>Source Device</th>
                <th>Virtual Server Name</th>
                <th>Virtual Server Destination</th>
                <th>Virtual Server VLAN</th>
                <th>Pool Member Name</th>
                <th>Pool Member IP</th>
                <th>Pool Member VLAN</th>
                <th>Certificate CN</th>
            </tr>
        </thead>
        <tbody>
"""

    for row in report_data:
        html_content += "            <tr>\n"

        # Add source device column
        html_content += f"                <td>{row['Source Device']}</td>\n"

        # Add hyperlink on virtual server name if present
        if row['Virtual Server Name']:
            html_content += f"                <td><a href='{row['Config Link']}' target='_blank'>{row['Virtual Server Name']}</a></td>\n"
        else:
            html_content += "                <td></td>\n"

        html_content += f"                <td>{row['Virtual Server Destination']}</td>\n"
        html_content += f"                <td>{row['Virtual Server VLAN']}</td>\n"
        html_content += f"                <td>{row['Pool Member Name']}</td>\n"
        html_content += f"                <td>{row['Pool Member IP']}</td>\n"
        html_content += f"                <td>{row['Pool Member VLAN']}</td>\n"
        html_content += f"                <td>{row['Certificate CN']}</td>\n"
        html_content += "            </tr>\n"

    html_content += """
        </tbody>
    </table>
</body>
</html>
"""

    # Write HTML file
    html_file = os.path.join(vs_dir, f"{base_filename}.html")
    with open(html_file, 'w', encoding='utf-8') as f:
        f.write(html_content)

    # Create zip file of the entire report directory
    zip_file = os.path.join(output_dir, f"{base_filename}.zip")
    shutil.make_archive(
        os.path.join(output_dir, base_filename),
        'zip',
        vs_dir
    )

    print(f"Virtual server report generated successfully!")
    print(f"HTML report: {html_file}")
    print(f"Excel report: {excel_file}")
    print(f"Configuration files: {config_dir}")
    print(f"Zip archive: {zip_file}")

    return {
        'html': html_file,
        'excel': excel_file,
        'config_dir': config_dir,
        'zip': zip_file
    }