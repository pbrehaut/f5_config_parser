"""
GTM Pool to LTM Virtual Server Mapping with Full Dependency Tree
=================================================================

This example demonstrates how to:
1. Map GTM server objects to their corresponding LTM devices
2. Map GTM pool members to actual virtual servers on LTM devices
3. Validate that GTM pool configurations are consistent
4. Extract complete dependency trees for each virtual server (pools, nodes,
   profiles, monitors, iRules, persistence, SSL certificates, etc.)
5. Map GTM pools to their dependent wide IPs

Use Case:
---------
When planning migrations, failovers, or audits, you need to understand not just
which virtual servers a GTM pool uses, but all the supporting configuration
those virtual servers depend on. This script provides a complete view of:
- Virtual servers referenced by GTM pools
- Backend pools and their members (nodes)
- Health monitors
- Profiles (HTTP, SSL, TCP, etc.)
- Persistence profiles
- iRules
- SSL certificates and keys
- Wide IPs that depend on each GTM pool
- Any other dependencies

This gives you a complete "slice" of configuration for each GTM pool.

Architecture:
-------------
Wide IP -> GTM Pool -> Virtual Server -> Pool -> Nodes
                                      -> Profiles (HTTP, SSL, TCP, etc.)
                                      -> Monitors
                                      -> Persistence
                                      -> iRules
                                      -> SSL Certs/Keys

Data Structures:
----------------
The script builds several key data structures for interrogation:

1. gtm_server_to_ltm: Dict mapping GTM server full paths to LTM device names
   - Key: GTM server full path (e.g., "gtm server server_name")
   - Value: LTM device identifier (e.g., 'ltm1', 'ltm3')

2. expected_pool_to_ltm: List of tuples showing expected GTM pool to LTM mappings
   - Format: [(gtm_pool_path, expected_ltm_name), ...]
   - Based on GTM server references in pool members

3. actual_pool_vips: Dict of StanzaCollections containing discovered virtual servers
   - Key: (gtm_pool_path, ltm_name)
   - Value: StanzaCollection of related objects (primarily virtual servers)
   - Only includes validated mappings that match expected configurations

4. complete_config_trees: Dict of complete dependency trees per GTM pool
   - Key: (gtm_pool_path, ltm_name)
   - Value: StanzaCollection containing:
     * Virtual servers
     * All LTM dependencies (pools, nodes, monitors, profiles, iRules, certs)
     * Dependent wide IPs from GTM
   - This is the primary output structure for further analysis

All StanzaCollections can be filtered, queried, and exported as needed for
detailed analysis or reporting.
"""


from pathlib import Path
from f5_config_parser.ucs import UCS


# Define input UCS files for analysis
input_files = [
    r"C:\path\to\configs\gtm_primary_device.ucs",
    r"C:\path\to\configs\gtm_secondary_device.ucs",
    r"C:\path\to\configs\ltm_device_01.ucs",
    r"C:\path\to\configs\ltm_device_02.ucs",
    r"C:\path\to\configs\ltm_device_03.ucs",
    r"C:\path\to\configs\ltm_device_04.ucs"
]


# Load all configurations into collections
collections = {}

print("Loading configurations...")
for file in input_files:
    with UCS(file) as ucs:
        collection = ucs.load_collection()
        collections[Path(file).name] = collection
    print(f"  Loaded: {Path(file).name}")


# Identify GTM and LTM collections
# Update these keys to match your actual filenames
gtm_primary = collections['gtm_primary_device.ucs']

ltm1 = collections['ltm_device_01.ucs']
ltm2 = collections['ltm_device_02.ucs']
ltm3 = collections['ltm_device_03.ucs']
ltm4 = collections['ltm_device_04.ucs']

ltm_collections = {
    'ltm1': ltm1,
    'ltm2': ltm2,
    'ltm3': ltm3,
    'ltm4': ltm4
}


print("\n" + "=" * 80)
print("PHASE 1: Mapping GTM Servers to LTM Devices")
print("=" * 80)

# Extract all GTM server objects
# Each GTM server represents a physical LTM device
gtm_servers = gtm_primary.filter(prefix=("gtm", "server"))
gtm_servers.reset_all_stanza_relations()

# Map each GTM server to its corresponding LTM device
# This discovers which LTM contains network objects that match the GTM server config
# Result: gtm_server_to_ltm dict maps GTM server paths to LTM device names
gtm_server_to_ltm = {}

for gtm_server in gtm_servers:
    for ltm_name, ltm_collection in ltm_collections.items():
        # Find related network objects (self-IPs, VLANs, routes) on this LTM
        related_objects = ltm_collection.get_related_stanzas([gtm_server])

        # If we found significant related configuration, this LTM matches the GTM server
        if len(related_objects) > 1:
            gtm_server_to_ltm[gtm_server.full_path] = ltm_name
            print(f"  Mapped: {gtm_server.name} -> {ltm_name}")
            break

        # Reset for next LTM search
        gtm_server.reset_all_relations()

print(f"\nTotal: {len(gtm_server_to_ltm)} GTM servers mapped")


print("\n" + "=" * 80)
print("PHASE 2: Mapping GTM Pools to Virtual Servers")
print("=" * 80)

# Extract all GTM pools
# Pools contain members that reference virtual servers on LTM devices
gtm_pools = gtm_primary.filter(prefix=("gtm", "pool"))
gtm_pools.reset_all_stanza_relations()

# Build expected mappings based on GTM server references
# Result: expected_pool_to_ltm list shows which LTMs should host each pool's virtual servers
expected_pool_to_ltm = []

# Discover actual virtual servers on LTMs
# Result: actual_pool_vips dict contains validated virtual server mappings
actual_pool_vips = {}

for gtm_pool in gtm_pools:
    # Parse pool members to determine expected LTM device locations
    # Pool member format: "server_name:virtual_server_name"
    pool_members = gtm_pool.parsed_config.get('members', {})

    if pool_members:
        for member_name in pool_members.keys():
            # Extract server and virtual server names from member
            server_name, virtual_server_name = member_name.split(':')

            # Look up which LTM this GTM server corresponds to
            server_full_path = f"gtm server {server_name}"
            expected_ltm = gtm_server_to_ltm.get(server_full_path, 'UNKNOWN')

            # Record the expected mapping
            expected_pool_to_ltm.append((gtm_pool.full_path, expected_ltm))

    # Discover which LTMs actually have virtual servers related to this pool
    for ltm_name, ltm_collection in ltm_collections.items():
        # Discover related objects (should be virtual servers) on this LTM
        related_objects = ltm_collection.get_related_stanzas([gtm_pool])

        # If we found virtual servers, record them
        if len(related_objects) > 1:
            key = (gtm_pool.full_path, ltm_name)
            actual_pool_vips[key] = related_objects

        # Reset for next LTM search
        gtm_pool.reset_all_relations()

print(f"Found virtual servers for {len(actual_pool_vips)} pool-LTM combinations")


print("\n" + "=" * 80)
print("PHASE 3: Validation - Checking Configuration Consistency")
print("=" * 80)

# Validate that actual virtual server locations match expected locations
# based on GTM server mappings. Remove any inconsistent mappings.
mismatches = []

for pool_ltm_combo in list(actual_pool_vips.keys()):
    # If we found virtual servers on an LTM, but the pool's GTM server
    # reference doesn't point to that LTM, we have a configuration issue
    if pool_ltm_combo not in expected_pool_to_ltm:
        mismatches.append(pool_ltm_combo)
        # Remove from results as this is an invalid configuration
        del actual_pool_vips[pool_ltm_combo]

if not mismatches:
    print("✓ All GTM pool configurations are consistent")
else:
    print(f"⚠ Found {len(mismatches)} configuration mismatches (removed from results)")


print("\n" + "=" * 80)
print("PHASE 4: Extracting Complete Dependency Trees")
print("=" * 80)

# For each valid GTM pool mapping, extract the complete dependency tree
# This includes all objects that the virtual servers depend on, plus wide IPs
# Result: complete_config_trees dict contains full configuration slices
complete_config_trees = {}

for (pool_path, ltm_name), initial_objects in actual_pool_vips.items():
    # Filter to get just the virtual servers from initial discovery
    vips = initial_objects.filter(prefix=("ltm", "virtual"))

    # Get the LTM collection for this device
    ltm_collection = ltm_collections[ltm_name]

    # For each virtual server, get ALL its dependencies recursively
    # This will include pools, nodes, profiles, monitors, iRules, certs, etc.
    all_vip_stanzas = []

    for vip in vips:
        # Reset the virtual server's relations before getting full tree
        vip.reset_all_relations()

        # Get complete dependency tree for this virtual server
        # This recursively discovers:
        # - Pools referenced by the VS
        # - Nodes in those pools
        # - Monitors for pools and nodes
        # - Profiles (HTTP, TCP, SSL, etc.)
        # - Persistence profiles
        # - iRules
        # - SSL certificates and keys
        # - Any other dependencies
        vip_dependencies = ltm_collection.get_related_stanzas([vip], relation_type='dependencies')

        all_vip_stanzas.append(vip)

    # Combine all virtual servers and their dependencies into one complete tree
    complete_tree = ltm_collection.get_related_stanzas(all_vip_stanzas, relation_type='dependencies')

    # Add dependent wide IPs from GTM configuration
    # This completes the full picture: Wide IP -> Pool -> VS -> Dependencies
    gtm_pool_stanza = gtm_primary[pool_path]
    gtm_pool_related_wideips = gtm_primary.get_related_stanzas([gtm_pool_stanza], relation_type='dependents')
    complete_tree += gtm_pool_related_wideips

    # Store the complete configuration tree
    complete_config_trees[(pool_path, ltm_name)] = complete_tree

print(f"Extracted {len(complete_config_trees)} complete configuration trees")


print("\n" + "=" * 80)
print("Data Structures Ready for Analysis")
print("=" * 80)
print("""
The following data structures are now available for interrogation:

1. gtm_server_to_ltm: GTM server to LTM device mappings
2. expected_pool_to_ltm: Expected pool-to-LTM relationships
3. actual_pool_vips: Validated virtual server discoveries
4. complete_config_trees: Full dependency trees including wide IPs

Each complete_config_trees entry contains:
- Virtual servers
- All LTM dependencies (pools, nodes, monitors, profiles, iRules, certificates)
- Dependent wide IPs

Use StanzaCollection methods to filter, query, and export as needed.
""")