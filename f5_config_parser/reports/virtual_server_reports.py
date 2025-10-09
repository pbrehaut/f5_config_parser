from f5_config_parser import load_collection_with_certificates
import pandas as pd
import os
from typing import Dict, List


def generate_virtual_server_report(
        input_file: str,
        tar_file: str,
        output_dir: str
) -> Dict[str, str]:
    """
    Generate virtual server report with network dependencies.

    Args:
        input_file: Path to the F5 configuration file
        tar_file: Path to the tar file containing certificates
        output_dir: Directory where reports and configs will be saved

    Returns:
        Dictionary containing paths to generated files:
        - 'html': Path to HTML report
        - 'excel': Path to Excel report
        - 'config_dir': Path to directory containing config files
    """
    # Create output directories
    config_dir = os.path.join(output_dir, "configs")
    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(config_dir, exist_ok=True)

    # Load configuration
    all_stanzas = load_collection_with_certificates(input_file, tar_file)

    # List to store report rows
    report_data = []

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

        # Create a safe filename from the virtual server name
        safe_name = vs.name.replace('/', '_').replace('\\', '_')
        config_filename = f"{safe_name}.txt"
        config_filepath = os.path.join(config_dir, config_filename)

        # Write the configuration to file
        with open(config_filepath, 'w', encoding='utf-8') as f:
            f.write(str(vs_all))

        # Determine maximum number of rows needed
        max_rows = max(len(pool_members), len(cert_cns), len(vs_vlans), 1)

        # Convert sets to sorted lists for indexing
        vs_vlans_list = sorted(vs_vlans)

        # Create rows
        for i in range(max_rows):
            row = {
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
    excel_file = os.path.join(output_dir, "virtual_server_report.xlsx")
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
    html_file = os.path.join(output_dir, "virtual_server_report.html")
    with open(html_file, 'w', encoding='utf-8') as f:
        f.write(html_content)

    print(f"Report generated successfully!")
    print(f"HTML report: {html_file}")
    print(f"Excel report: {excel_file}")
    print(f"Configuration files: {config_dir}")

    return {
        'html': html_file,
        'excel': excel_file,
        'config_dir': config_dir
    }
