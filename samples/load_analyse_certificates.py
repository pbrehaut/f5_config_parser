from f5_config_parser import load_collection_from_archive
import re

# Input file paths - replace with your actual file paths
INPUT_FILE = r"/path/to/your/f5_config_directory"
TAR_FILE = r"/path/to/your/f5_config_archive.tar"

# Load the F5 configuration along with certificate data
all_stanzas = load_collection_from_archive(config_path=INPUT_FILE, archive_path=TAR_FILE)

# Example 1: Extract all certificate objects and their OCSP URIs
# Filter to get only certificate objects from the configuration
certs = all_stanzas.filter(('certificate', 'object'))

# Extract unique OCSP URIs from all certificates
ocsp = set([x.parsed_config.get('ocsp_uri') for x in certs])

# Example 2: Find certificates matching a specific domain pattern and trace their usage
# Search for certificates with subjects matching a particular domain pattern
# Replace the regex pattern with your domain of interest (e.g., r'example\.com')
domain_pattern = re.compile(r'(subdomain1|subdomain2)\.domain\.example\.com')
matching_certs = all_stanzas.filter(subject=domain_pattern)

# Find all virtual servers that use these certificates
# This traces the certificate usage through the configuration dependencies
matching_vs = all_stanzas.get_related_stanzas(
    matching_certs,
    relation_type='dependents'
).filter(('ltm', 'virtual'))

# Get all related configuration objects for these virtual servers
# This includes profiles, pools, monitors, and other dependencies
matching_all = all_stanzas.get_related_stanzas(matching_vs)

# Extract all certificates used in the related configuration
matching_all_certs = matching_all.filter(('certificate', 'object'))