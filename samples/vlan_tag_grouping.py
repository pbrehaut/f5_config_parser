from collections import defaultdict
from pathlib import Path
from f5_config_parser.collection import StanzaCollection
from f5_config_parser.certificates.certificate_loader import load_certificates_from_tar

# ============================================================================
# CONFIGURATION SECTION - Update these values for your environment
# ============================================================================

# TODO: Set the base directory containing your F5 configuration files
# Example: base_dir = Path(r"C:\f5_configs") or Path("/home/user/f5_configs")
base_dir = Path(r"")

# TODO: Add your F5 device names to this list
# These names should match the filenames (without extensions) of your .scf and .scf.tar files
# Example: f5_devices = ["f5-prod-01", "f5-prod-02", "f5-test-01"]
f5_devices = []

# ============================================================================
# LOAD F5 CONFIGURATIONS AND CERTIFICATES
# ============================================================================

# Dictionary to store StanzaCollection objects for each device
collections = {}

# Process each F5 device
for device in f5_devices:
    # Construct file paths for configuration and certificate tar files
    config_file = base_dir / f"{device}.scf"
    tar_file = base_dir / f"{device}.scf.tar"

    # Check if the configuration file exists
    if not config_file.exists():
        print(f"Config file not found for device {device}: {config_file}")
        continue

    # Load the F5 configuration file and parse it into a StanzaCollection
    with open(config_file) as f:
        collections[device] = StanzaCollection.from_config(f.read())

    # Load certificates if the tar file exists
    if tar_file.exists():
        # Extract and load certificates from the tar archive
        certificates = load_certificates_from_tar(str(tar_file))
        # Add certificates to the device's collection
        collections[device] += certificates
        # Build the dependency graph for the configuration objects
        collections[device].initialise_dependencies()
    else:
        print(f"Certificate tar file not found for device {device}: {tar_file}")

    # Cache the dependency information for faster future access
    collections[device].save_dependency_cache()

# ============================================================================
# ANALYSE VLAN TAGS ACROSS DEVICES
# ============================================================================

# Dictionary mapping VLAN tags to the set of devices using that tag
# defaultdict(set) automatically creates an empty set for new keys
vlan_tags = defaultdict(set)

# Extract VLAN tags from each device's configuration
for device in f5_devices:
    # Skip devices that failed to load
    if device not in collections:
        continue

    # Get all VLAN configuration stanzas and extract their tag values
    # Filter for objects with prefix ('net', 'vlan') and extract the 'tag' field
    device_tags = {x.parsed_config.get('tag') for x in collections[device].filter(prefix=('net', 'vlan'))}

    # Associate each tag with this device
    for tag in device_tags:
        vlan_tags[tag].add(device)

# ============================================================================
# REPORT VLAN TAG USAGE
# ============================================================================

# Print VLAN tags and which devices use them
# Tags used by multiple devices indicate shared VLANs
for tag, devices in sorted(vlan_tags.items()):
    if len(devices) > 1:
        # Tag is shared across multiple devices
        print(f"Tag {tag}: {', '.join(sorted(devices))}")
    else:
        # Tag is only used on one device
        print(f"Tag {tag}: {', '.join(sorted(devices))} (Unique)")