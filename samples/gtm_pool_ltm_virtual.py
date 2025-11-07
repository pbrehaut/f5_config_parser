"""
GTM Pool to LTM Virtual Server Mapping with Full Dependency Tree
=================================================================

This example demonstrates how to:
1. Map GTM server objects to their corresponding LTM devices
2. Map GTM pool members to actual virtual servers on LTM devices
3. Validate that GTM pool configurations are consistent
4. Extract complete dependency trees for each virtual server (pools, nodes,
   profiles, monitors, iRules, persistence, SSL certificates, etc.)

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
- Any other dependencies

This gives you a complete "slice" of configuration for each GTM pool.

Architecture:
-------------
GTM Pool -> Virtual Server -> Pool -> Nodes
                           -> Profiles (HTTP, SSL, TCP, etc.)
                           -> Monitors
                           -> Persistence
                           -> iRules
                           -> SSL Certs/Keys
"""

from pathlib import Path
from f5_config_parser.ucs import UCS

# Define input UCS files for analysis
input_files = [
    r"C:\configs\gtm-primary.ucs",
    r"C:\configs\gtm-secondary.ucs",
    r"C:\configs\ltm-datacenter-a-01.ucs",
    r"C:\configs\ltm-datacenter-a-02.ucs",
    r"C:\configs\ltm-datacenter-b-01.ucs",
    r"C:\configs\ltm-datacenter-b-02.ucs"
]

# Load all configurations into collections
collections = {}

print("Loading configurations...")
for file in input_files:
    with UCS(file) as ucs:
        collection = ucs.load_collection()
        collections[Path(file).name] = collection
    print(f"  Loaded: {Path(file).name}")

# Assign collections to meaningful variables
gtm_primary = collections['gtm-primary.ucs']

ltm_dc_a_01 = collections['ltm-datacenter-a-01.ucs']
ltm_dc_a_02 = collections['ltm-datacenter-a-02.ucs']
ltm_dc_b_01 = collections['ltm-datacenter-b-01.ucs']
ltm_dc_b_02 = collections['ltm-datacenter-b-02.ucs']

# Create a dictionary of LTM collections for iteration
ltm_collections = {
    'ltm-dc-a-01': ltm_dc_a_01,
    'ltm-dc-a-02': ltm_dc_a_02,
    'ltm-dc-b-01': ltm_dc_b_01,
    'ltm-dc-b-02': ltm_dc_b_02
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
gtm_server_to_ltm = {}

for gtm_server in gtm_servers:
    print(f"\nAnalysing GTM server: {gtm_server.name}")

    for ltm_name, ltm_collection in ltm_collections.items():
        # Find related network objects (self-IPs, VLANs, routes) on this LTM
        related_objects = ltm_collection.get_related_stanzas([gtm_server])

        # If we found significant related configuration, this LTM matches the GTM server
        if len(related_objects) > 1:
            gtm_server_to_ltm[gtm_server.full_path] = ltm_name
            print(f"  ✓ Mapped to: {ltm_name} ({len(related_objects)} related objects)")
            break

        # Reset for next LTM search
        gtm_server.reset_all_relations()

print(f"\nMapped {len(gtm_server_to_ltm)} GTM servers to LTM devices")

print("\n" + "=" * 80)
print("PHASE 2: Mapping GTM Pools to Virtual Servers")
print("=" * 80)

# Extract all GTM pools
# Pools contain members that reference virtual servers on LTM devices
gtm_pools = gtm_primary.filter(prefix=("gtm", "pool"))
gtm_pools.reset_all_stanza_relations()

# Track expected mappings based on GTM server references
# Format: [(gtm_pool_path, expected_ltm_name), ...]
expected_pool_to_ltm = []

# Track actual virtual servers found on each LTM
# Format: {(gtm_pool_path, ltm_name): StanzaCollection, ...}
actual_pool_vips = {}

for gtm_pool in gtm_pools:
    print(f"\nAnalysing GTM pool: {gtm_pool.name}")

    # Parse pool members to determine which LTM devices should have the virtual servers
    # Pool member format: "server_name:virtual_server_name"
    pool_members = gtm_pool.parsed_config.get('members', {})

    if pool_members:
        print(f"  Pool has {len(pool_members)} members:")

        for member_name in pool_members.keys():
            # Extract server and virtual server names from member
            server_name, virtual_server_name = member_name.split(':')

            # Look up which LTM this GTM server corresponds to
            server_full_path = f"gtm server {server_name}"
            expected_ltm = gtm_server_to_ltm.get(server_full_path, 'UNKNOWN')

            print(f"    {member_name} -> expected on {expected_ltm}")

            # Record the expected mapping
            expected_pool_to_ltm.append((gtm_pool.full_path, expected_ltm))

    # Now discover which LTMs actually have virtual servers related to this pool
    print("  Searching for actual virtual servers on LTMs...")

    for ltm_name, ltm_collection in ltm_collections.items():
        # Discover related objects (should be virtual servers) on this LTM
        related_objects = ltm_collection.get_related_stanzas([gtm_pool])

        # If we found virtual servers, record them
        if len(related_objects) > 1:
            key = (gtm_pool.full_path, ltm_name)
            actual_pool_vips[key] = related_objects

            # Count virtual servers found
            vips = related_objects.filter(prefix=("ltm", "virtual"))
            print(f"    ✓ Found {len(vips)} virtual servers on {ltm_name}")

        # Reset for next LTM search
        gtm_pool.reset_all_relations()

print(f"\nFound virtual servers for {len(actual_pool_vips)} pool-LTM combinations")

print("\n" + "=" * 80)
print("PHASE 3: Validation - Checking for Mismatches")
print("=" * 80)

# Validate that actual virtual server locations match expected locations
# based on GTM server mappings
mismatches = []

for pool_ltm_combo in list(actual_pool_vips.keys()):
    # If we found virtual servers on an LTM, but the pool's GTM server
    # reference doesn't point to that LTM, we have a configuration issue
    if pool_ltm_combo not in expected_pool_to_ltm:
        mismatches.append(pool_ltm_combo)
        print(f"\n⚠ MISMATCH DETECTED:")
        print(f"  Pool: {pool_ltm_combo[0]}")
        print(f"  Found virtual servers on: {pool_ltm_combo[1]}")
        print(f"  But pool's GTM server references don't point to this LTM")

        # Remove from results as this is an invalid configuration
        del actual_pool_vips[pool_ltm_combo]

if not mismatches:
    print("\n✓ All GTM pool configurations are consistent!")
    print("  All virtual servers found on expected LTM devices.")
else:
    print(f"\n✗ Found {len(mismatches)} configuration mismatches")
    print("  These should be reviewed and corrected.")

print("\n" + "=" * 80)
print("PHASE 4: Extracting Complete Dependency Trees")
print("=" * 80)

# For each valid GTM pool mapping, extract the complete dependency tree
# This includes all objects that the virtual servers depend on
complete_config_trees = {}

for (pool_path, ltm_name), initial_objects in actual_pool_vips.items():
    print(f"\nExtracting full dependency tree for: {pool_path}")
    print(f"  LTM Device: {ltm_name}")

    # Filter to get just the virtual servers from initial discovery
    vips = initial_objects.filter(prefix=("ltm", "virtual"))
    print(f"  Virtual servers: {len(vips)}")

    # Get the LTM collection for this device
    ltm_collection = ltm_collections[ltm_name]

    # For each virtual server, get ALL its dependencies recursively
    # This will include pools, nodes, profiles, monitors, iRules, certs, etc.
    all_vip_stanzas = []

    for vip in vips:
        print(f"    Processing: {vip.name}")

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

        print(f"      Found {len(vip_dependencies)} total dependencies")

        # Show breakdown by object type
        for prefix_tuple in [("ltm", "pool"), ("ltm", "node"), ("ltm", "monitor"),
                             ("ltm", "profile"), ("ltm", "persistence"), ("ltm", "rule"),
                             ("sys", "file", "ssl-cert"), ("sys", "file", "ssl-key")]:
            filtered = vip_dependencies.filter(prefix=prefix_tuple)
            if len(filtered) > 0:
                prefix_str = ' '.join(prefix_tuple)
                print(f"        - {prefix_str}: {len(filtered)}")

    # Combine all virtual servers and their dependencies into one complete tree
    complete_tree = ltm_collection.get_related_stanzas(all_vip_stanzas, relation_type='dependencies')

    # Store the complete configuration tree
    complete_config_trees[(pool_path, ltm_name)] = complete_tree

    print(f"  ✓ Complete configuration tree: {len(complete_tree)} total objects")

print("\n" + "=" * 80)
print("SUMMARY")
print("=" * 80)

print(f"\nGTM Servers mapped: {len(gtm_server_to_ltm)}")
print(f"GTM Pools analysed: {len(gtm_pools)}")
print(f"Valid pool-to-VIP mappings: {len(actual_pool_vips)}")
print(f"Configuration mismatches: {len(mismatches)}")
print(f"Complete configuration trees extracted: {len(complete_config_trees)}")

# Display detailed breakdown of configuration trees
if complete_config_trees:
    print("\n" + "=" * 80)
    print("Complete Configuration Trees by GTM Pool")
    print("=" * 80)

    for (pool_path, ltm_name), config_tree in complete_config_trees.items():
        print(f"\n{pool_path} on {ltm_name}")
        print(f"  Total objects: {len(config_tree)}")

        # Get breakdown by object type
        type_counts = {}
        for stanza in config_tree:
            prefix_str = ' '.join(stanza.prefix[:2])  # Get first two levels (e.g., "ltm pool")
            type_counts[prefix_str] = type_counts.get(prefix_str, 0) + 1

        print("  Object breakdown:")
        for obj_type, count in sorted(type_counts.items()):
            print(f"    {obj_type}: {count}")

# Example: Export complete configuration trees to files
print("\n" + "=" * 80)
print("Exporting configuration trees...")
print("=" * 80)

for (pool_path, ltm_name), config_tree in complete_config_trees.items():
    # Create safe filename from pool path
    pool_name = pool_path.split()[-1].replace('/', '_')
    output_file = f"gtm_pool_{pool_name}_on_{ltm_name}_COMPLETE.conf"

    # Sort the configuration tree for better readability
    # Virtual servers will appear first, followed by dependencies
    sorted_tree = config_tree.sort()

    with open(output_file, 'w') as f:
        f.write(f"# GTM Pool: {pool_path}\n")
        f.write(f"# LTM Device: {ltm_name}\n")
        f.write(f"# Complete Configuration Tree\n")
        f.write(f"#\n")
        f.write(f"# This file contains the complete configuration needed for this GTM pool:\n")
        f.write(f"# - Virtual servers referenced by the GTM pool\n")
        f.write(f"# - Backend pools and their members\n")
        f.write(f"# - Health monitors\n")
        f.write(f"# - Profiles (HTTP, SSL, TCP, etc.)\n")
        f.write(f"# - Persistence profiles\n")
        f.write(f"# - iRules\n")
        f.write(f"# - SSL certificates and keys\n")
        f.write(f"# - All other dependencies\n")
        f.write(f"#\n")
        f.write(f"# Total objects: {len(config_tree)}\n")
        f.write(f"#\n\n")
        f.write(str(sorted_tree))

    print(f"  ✓ Exported: {output_file} ({len(config_tree)} objects)")

print("\n✓ Analysis complete!")
print("\nThese complete configuration files can be used for:")
print("  - Migration planning (know exactly what to move)")
print("  - Impact analysis (understand dependencies)")
print("  - Documentation (complete view of each GTM pool)")
print("  - Disaster recovery (rebuild configuration if needed)")