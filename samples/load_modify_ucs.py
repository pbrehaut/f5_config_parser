from f5_config_parser.ucs import UCS

# List of F5 UCS archive files to process
input_files = ['f51.ucs',
               'f52.ucs']

# Dictionary to store collections from each UCS file
# Key: filename, Value: StanzaCollection object
collections = {}

# Process each UCS file
for file in input_files:
    # Use context manager to ensure cleanup of temporary files
    # UCS extracts the archive to a temp directory during processing
    with UCS(file) as ucs:
        # Load the complete configuration from the UCS archive
        # This parses all config files and certificates into a StanzaCollection
        collection = ucs.load_collection()

        # Store collection for potential further processing
        collections[file] = collection

        # Filter to get only VLAN configuration objects
        # Returns all stanzas matching the prefix ('net', 'vlan')
        vlans = collection.filter(('net', 'vlan'))

        # Modify each VLAN configuration
        # Replace partition references from /Common/ to /Partition_1/
        for vlan in vlans:
            vlan.config_lines[0] = vlan.config_lines[0].replace('/Common/', '/Partition_1/')

        # Write the modified collection back to a new UCS archive
        # Original file: f51.ucs -> Output file: f51_updated.ucs
        # Only config files with modified stanzas are rewritten
        # Certificates and unmodified files remain intact
        ucs.write_back_collection(collection, file.replace('.ucs', '_updated.ucs'))