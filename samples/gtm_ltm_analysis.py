"""
Cross-Device GTM to LTM Analysis
=================================

This example demonstrates how to analyse GTM server objects and discover which
LTM devices they connect to by finding related network configuration objects
(self-IPs, routes, etc.) on each LTM.

Use Case:
---------
When you have multiple GTM and LTM devices, you may need to understand which
LTM interfaces the GTM servers connect through. This script:
1. Loads configurations from multiple devices
2. Extracts GTM server objects
3. For each GTM server, discovers related network objects on each LTM
4. Maps which LTM device(s) contain the related network configuration

Key Technique:
--------------
The script uses `reset_all_relations()` between discoveries to allow the same
GTM server object to be analysed against multiple LTM collections. Without
resetting, cached dependencies from the first LTM would prevent discovery
against subsequent LTMs.
"""

from pathlib import Path
from f5_config_parser.ucs import UCS

# Define input UCS files for analysis
# Typically you'd have 2 GTMs (HA pair) and multiple LTMs
input_files = [
    r"C:\configs\gtm-primary.ucs",
    r"C:\configs\gtm-secondary.ucs",
    r"C:\configs\ltm-site-a-01.ucs",
    r"C:\configs\ltm-site-a-02.ucs",
    r"C:\configs\ltm-site-b-01.ucs",
    r"C:\configs\ltm-site-b-02.ucs"
]

# Load all configurations into a dictionary
# Key: filename, Value: StanzaCollection
collections = {}

for file in input_files:
    with UCS(file) as ucs:
        collection = ucs.load_collection()
        collections[Path(file).name] = collection

# Assign collections to meaningful variable names for clarity
gtm_primary = collections['gtm-primary.ucs']
gtm_secondary = collections['gtm-secondary.ucs']

ltm_site_a_01 = collections['ltm-site-a-01.ucs']
ltm_site_a_02 = collections['ltm-site-a-02.ucs']
ltm_site_b_01 = collections['ltm-site-b-01.ucs']
ltm_site_b_02 = collections['ltm-site-b-02.ucs']

# Extract all GTM server objects from the primary GTM
# GTM servers represent the LTM devices that GTM distributes traffic to
gtm_servers = gtm_primary.filter(prefix=("gtm", "server"))

# Reset all relationships on GTM servers before cross-device analysis
# This clears any dependencies that were discovered during initial collection loading
gtm_servers.reset_all_stanza_relations()

# Create a dictionary to map LTM devices for iteration
ltm_devices = {
    'ltm-site-a-01': ltm_site_a_01,
    'ltm-site-a-02': ltm_site_a_02,
    'ltm-site-b-01': ltm_site_b_01,
    'ltm-site-b-02': ltm_site_b_02
}

# Main analysis: Map each GTM server to related objects on each LTM
# This discovers which LTM contains the network configuration (self-IPs, routes)
# that the GTM server connects through
gtm_to_ltm_map = {}

for gtm_server in gtm_servers:
    print(f"Analysing GTM server: {gtm_server.name}")

    for ltm_name, ltm_collection in ltm_devices.items():
        # Build a descriptive key for the mapping
        map_key = f"{gtm_server.name} -> {ltm_name}"

        # Discover all related objects on this specific LTM
        # This searches for network objects (self-IPs, VLANs, routes) that match
        # the GTM server's configuration
        related_objects = ltm_collection.get_related_stanzas([gtm_server])

        # Store the results
        gtm_to_ltm_map[map_key] = related_objects

        # CRITICAL: Reset the GTM server's cached relationships
        # This allows the next LTM collection to perform a fresh discovery
        # Without this, the cached dependencies from the current LTM would be
        # returned for all subsequent LTMs
        gtm_server.reset_all_relations()

        # Print summary of what was found
        if len(related_objects) > 0:
            print(f"  Found {len(related_objects)} related objects on {ltm_name}")

# Analysis complete - gtm_to_ltm_map now contains the cross-device relationships
print("\nAnalysis Summary:")
print("=" * 80)

for map_key, related_collection in gtm_to_ltm_map.items():
    if len(related_collection) > 0:
        print(f"\n{map_key}:")
        print(f"  Total related objects: {len(related_collection)}")

        # Show breakdown by object type
        prefixes = {}
        for stanza in related_collection:
            prefix_str = ' '.join(stanza.prefix)
            prefixes[prefix_str] = prefixes.get(prefix_str, 0) + 1

        for prefix, count in sorted(prefixes.items()):
            print(f"    {prefix}: {count}")

# Example: Export related objects for a specific GTM server to a file
# Uncomment and modify as needed:
"""
specific_server = "gtm_server_name"
for map_key, related_collection in gtm_to_ltm_map.items():
    if specific_server in map_key and len(related_collection) > 0:
        output_file = f"{map_key.replace(' -> ', '_to_')}.conf"
        with open(output_file, 'w') as f:
            f.write(str(related_collection))
        print(f"Exported: {output_file}")
"""