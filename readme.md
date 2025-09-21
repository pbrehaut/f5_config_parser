# F5 Configuration Parser

A Python library for parsing, analysing, and manipulating F5 BIG-IP configuration files. This library provides object-oriented access to F5 configurations with automatic dependency resolution, change tracking, network topology mapping, and powerful filtering capabilities.

## Table of Contents
- [Features](#features)
- [Installation](#installation)
  - [From source](#from-source)
- [Quick Start](#quick-start)
  - [Basic Usage](#basic-usage)
  - [Working with Certificates](#working-with-certificates)
  - [Working with Collections](#working-with-collections)
- [Core Components](#core-components)
  - [ConfigStanza](#configstanza)
  - [Certificate](#certificate)
  - [StanzaCollection](#stanzacollection)
- [Advanced Features](#advanced-features)
  - [Certificate Management and Analysis](#certificate-management-and-analysis)
  - [Certificate Comparison Between Devices](#certificate-comparison-between-devices)
  - [Complete SSL Dependency Chain Analysis](#complete-ssl-dependency-chain-analysis)
  - [Collection Operations - Adding and Removing Stanzas](#collection-operations---adding-and-removing-stanzas)
  - [Dependency Analysis](#dependency-analysis)
  - [iRule Dependency Detection](#irule-dependency-detection)
  - [Network Dependency Mapping](#network-dependency-mapping)
  - [Change Tracking](#change-tracking)
  - [Advanced Filtering](#advanced-filtering)
- [Practical Use Cases](#practical-use-cases)
  - [Configuration Manipulation and Deployment](#configuration-manipulation-and-deployment)
  - [Virtual Server Deletion with Safe Dependency Removal](#virtual-server-deletion-with-safe-dependency-removal)
  - [Orphaned Configuration Cleanup](#orphaned-configuration-cleanup)
  - [Finding Virtual Servers by Profile Type](#finding-virtual-servers-by-profile-type)
  - [Configuration Drift Detection Between F5 Devices](#configuration-drift-detection-between-f5-devices)
  - [Finding Pool Members with Specific Priority Groups](#finding-pool-members-with-specific-priority-groups)
  - [Complex Filtering with Set Operations on Single Collections](#complex-filtering-with-set-operations-on-single-collections)
  - [Finding Which Network Objects Contain Pool Members](#finding-which-network-objects-contain-pool-members)
- [Outputting Configuration](#outputting-configuration)
- [Performance Considerations](#performance-considerations)
  - [Lazy Initialisation](#lazy-initialisation)
  - [Selective Dependency Resolution](#selective-dependency-resolution)
- [Error Handling and Logging](#error-handling-and-logging)
  - [Configuration Validation](#configuration-validation)
  - [Validation Process](#validation-process)
  - [Understanding the Validation Log](#understanding-the-validation-log)
  - [Common Validation Errors and Solutions](#common-validation-errors-and-solutions)
  - [When to Check the Validation Log](#when-to-check-the-validation-log)
- [Requirements](#requirements)
- [Project Structure](#project-structure)
- [Testing](#testing)
- [API Documentation](#api-documentation)
  - [Generating Documentation Locally](#generating-documentation-locally)
- [Contributing](#contributing)
- [License](#license)

## Features

- **Comprehensive Parsing**: Parse F5 configuration files into structured Python objects
- **Certificate Management**: Load and analyse SSL certificates and keys from F5 tar archives
- **Dependency Analysis**: Automatically discover and resolve object dependencies including SSL profiles to certificates
- **Network Topology Mapping**: Trace network dependencies from virtual servers through routes, self IPs, VLANs, and interfaces
- **Change Tracking**: Monitor and log all configuration modifications
- **Flexible Filtering**: Query configurations using prefix, name, content, and parsed config filters
- **Collection Operations**: Bulk operations on configuration stanzas with set-like operations
- **Type-Specific Handling**: Specialised parsers for different F5 object types (virtual servers, pools, profiles, etc.)

## Installation

### From source

```bash
git clone https://github.com/pbrehaut/f5-config-parser.git
cd f5-config-parser
```

## Quick Start

### Basic Usage

```python
from f5_config_parser.collection import StanzaCollection

# Parse a configuration file
with open('bigip.conf', 'r') as f:
    config_text = f.read()

# Create collection with full initialisation
collection = StanzaCollection.from_config(config_text)

# Access individual stanzas
vs = collection['ltm virtual /Common/my-virtual-server']
print(f"Virtual server destination: {vs.parsed_config['destination']}")

# Filter configurations
virtual_servers = collection.filter(prefix=("ltm", "virtual"))
ssl_profiles = collection.filter(prefix=("ltm", "profile"), content="ssl")

# Analyse dependencies
dependencies = vs.get_dependencies(collection)
# or dependencies = vs.get_dependencies(collection) # Call with collection object if not initialised already.
# or dependencies = vs.get_dependencies(collection, force_rediscover=True) # Call with collection object and force_rediscover=True to force rediscovery with collection object as the scope.
print(f"Virtual server depends on: {dependencies}")
```

### Working with Certificates

```python
from f5_config_parser.certificates.certificate_loader import load_certificates_from_tar
from f5_config_parser.collection import StanzaCollection

# Load certificates from F5 tar archive
certificates = load_certificates_from_tar('f5_backup.tar', load_pem_data=True)

# Create collection from config and add certificates
collection = StanzaCollection.from_config(config_text)
collection += certificates

# Now SSL profiles can resolve dependencies to certificates
ssl_profile = collection['ltm profile client-ssl /Common/my-ssl-profile']

# force_rediscover is required here as the dependencies already would have been initialised when the config was loaded and needs to be refreshed 
# now that the certificates have been added. Alternatively initialise dependencies could be rerun on the entire collection, 
# see performance consideration section below, and certificate add example.
cert_dependencies = ssl_profile.get_dependencies(collection, force_rediscover=True)
cert_objects = collection.get_related_stanzas([ssl_profile], 'dependencies').filter(prefix=("certificate", "object"))

print(f"SSL profile uses certificates: {[cert.filename for cert in cert_objects]}")

# Find all certificates used by virtual servers
vs_stanzas = collection.filter(prefix=("ltm", "virtual"))
all_vs_deps = collection.get_related_stanzas(vs_stanzas.stanzas, 'dependencies')
used_certificates = all_vs_deps.filter(prefix=("certificate", "object"))
print(f"Certificates in use: {[cert.filename for cert in used_certificates]}")
```

### Working with Collections

```python
# Combine collections
prod_configs = StanzaCollection.from_config(prod_config_text)
dev_configs = StanzaCollection.from_config(dev_config_text)
all_configs = prod_configs + dev_configs

# Filter and analyse
web_servers = collection.filter(name=re.compile(r'web-\d+'))
related_objects = collection.get_related_stanzas(
    web_servers, 
    relation_type='dependencies'
)

# Bulk modifications
for vs in virtual_servers:
    vs.find_and_replace('old-pool', 'new-pool', match_type='word_boundary')
```

## Core Components

### ConfigStanza
The base class representing individual F5 configuration objects. Each stanza includes:
- **Prefix and Name**: Hierarchical object identification (`ltm virtual`, `net self`, etc.)
- **Configuration Lines**: Raw F5 configuration content with change monitoring
- **Parsed Config**: Structured dictionary representation of the configuration
- **Dependencies**: Automatic discovery of object relationships
- **Network Dependencies**: IP-based dependency resolution for network topology mapping

### Certificate
A specialised ConfigStanza representing SSL certificates and keys with:
- **Certificate Metadata**: Subject, issuer, serial number, validity dates
- **Key Pair Matching**: Automatic detection and verification of certificate/key pairs
- **CA Chain Resolution**: Discovery of issuing certificate authorities
- **PEM Data Access**: Optional loading of raw certificate and key data
- **Expiration Tracking**: Built-in validation date checking

### StanzaCollection
A powerful container for managing multiple configuration stanzas with:
- **Bulk Operations**: Add, remove, and filter stanzas using familiar Python operations
- **Dependency Resolution**: Automatically resolve object references within the collection
- **Network Topology Analysis**: Map complete network paths from applications to physical interfaces
- **Certificate Integration**: Seamlessly include certificates in dependency analysis
- **Validation**: Ensure configuration consistency and prevent duplicates
- **Relationship Analysis**: Discover transitive dependencies and dependents

## Advanced Features

### Certificate Management and Analysis

The library provides comprehensive certificate management capabilities that integrate seamlessly with F5 configuration analysis:

```python
from f5_config_parser.certificates.certificate_loader import load_certificates_from_tar
from datetime import datetime, timezone

# Load certificates with full metadata
certificates = load_certificates_from_tar('f5_backup.tar', load_pem_data=True)

# Filter by certificate properties
ca_certificates = [cert for cert in certificates if cert.is_ca]
expiring_soon = [cert for cert in certificates 
                 if cert.not_valid_after < datetime.now(timezone.utc).replace(month=12)]

# Verify certificate/key pairs
for cert in certificates:
    if not cert.is_ca and cert.key_pem_data:
        try:
            if cert.verify_key_match():
                print(f"✓ {cert.filename} - Certificate and key match")
            else:
                print(f"✗ {cert.filename} - Certificate and key mismatch")
        except ValueError as e:
            print(f"? {cert.filename} - Verification failed: {e}")

# Find certificate chains
for cert in certificates:
    if not cert.is_ca and cert.aki:
        # Find issuing CA
        issuing_ca = next((ca for ca in ca_certificates if ca.ski == cert.aki), None)
        if issuing_ca:
            print(f"{cert.filename} issued by {issuing_ca.filename}")
```

### Certificate Comparison Between Devices

A common operational task is comparing certificates between F5 devices to identify missing or outdated certificates:

```python
from f5_config_parser.certificates.certificate_loader import load_certificates_from_tar
from datetime import datetime, timezone
from collections import defaultdict

# Load certificates from two different F5 devices
old_device_certs = load_certificates_from_tar('device1_backup.tar', load_pem_data=True)
new_device_certs = load_certificates_from_tar('device2_backup.tar', load_pem_data=True)

# Get current time for expiration checking
current_time = datetime.now(timezone.utc)

# Filter out expired certificates
old_device_certs = [cert for cert in old_device_certs if cert.not_valid_after > current_time]
new_device_certs = [cert for cert in new_device_certs if cert.not_valid_after > current_time]

# Create sets of certificate IDs for efficient comparison
old_cert_ids = {cert.cert_id for cert in old_device_certs}
new_cert_ids = {cert.cert_id for cert in new_device_certs}

# Find certificates that exist on old device but are missing on new device
missing_cert_ids = old_cert_ids - new_cert_ids
extra_cert_ids = new_cert_ids - old_cert_ids

# Create lookup dictionaries
old_cert_lookup = defaultdict(list)
for cert in old_device_certs:
    old_cert_lookup[cert.cert_id].append(cert)

new_cert_lookup = defaultdict(list)
for cert in new_device_certs:
    new_cert_lookup[cert.cert_id].append(cert)

# Get the actual certificate objects that are missing
missing_certificates = [old_cert_lookup[cert_id] for cert_id in missing_cert_ids]
extra_certificates = [new_cert_lookup[cert_id] for cert_id in extra_cert_ids]

print(f"Certificates missing from new device: {len(missing_certificates)}")
for cert_list in missing_certificates:
    for cert in cert_list:
        print(f"  - {cert.filename} (Subject: {cert.subject})")

print(f"Extra certificates on new device: {len(extra_certificates)}")
for cert_list in extra_certificates:
    for cert in cert_list:
        print(f"  + {cert.filename} (Subject: {cert.subject})")
```

### Complete SSL Dependency Chain Analysis

With certificates integrated into the collection, you can now trace complete SSL dependency chains from virtual servers down to certificate files:

```python
# Load configuration and certificates
collection = StanzaCollection.from_config(config_text)
certificates = load_certificates_from_tar('f5_backup.tar', load_pem_data=True)

# Add certificates to collection
collection += certificates

# This method call is required in this instance to refresh stale dependencies that would have been initialised on config load above
# The dependency state for the SSL profile objects would be initialised but missing the certificate objects, running this method will force a refresh
# with the new scope available
# It is also recommended to save the dependency cache at this point for performance boost. See performance section below
collection.initialise_dependencies()

# Analyse complete SSL dependency chain
vs = collection['ltm virtual /Common/secure-web-server']
all_dependencies = collection.get_related_stanzas([vs], 'dependencies')

# Break down by dependency type
ssl_profiles = all_dependencies.filter(prefix=("ltm", "profile", "client-ssl"))
certificates = all_dependencies.filter(prefix=("certificate", "object"))

print(f"Virtual server {vs.name} SSL dependency chain:")
print(f"  SSL Profiles: {[profile.name for profile in ssl_profiles]}")
print(f"  Certificates: {[cert.filename for cert in certificates]}")

# Find unused certificates
all_vs = collection.filter(prefix=("ltm", "virtual"))
all_vs_deps = collection.get_related_stanzas(all_vs.stanzas, 'dependencies')
used_certs = all_vs_deps.filter(prefix=("certificate", "object"))
all_certs = collection.filter(prefix=("certificate", "object"))

unused_certs = all_certs - used_certs
print(f"Unused certificates: {[cert.filename for cert in unused_certs]}")
```

### Collection Operations - Adding and Removing Stanzas

Collections support standard Python operators for adding and removing stanzas, with all operations being logged to the stanza's change history:

```python
from f5_config_parser.collection import StanzaCollection

# Load initial collections
with open('config1.txt') as f:
    collection1 = StanzaCollection.from_config(f.read())
with open('config2.txt') as f:
    collection2 = StanzaCollection.from_config(f.read())

# Create new collection by combining (non-destructive)
combined = collection1 + collection2  # Creates new collection with both sets

# Add stanzas in-place (modifies existing collection)
collection1 += collection2  # Adds all stanzas from collection2 to collection1

# Remove stanzas to create new collection
filtered = collection1 - collection1.filter(prefix=('ltm', 'monitor'))  # New collection without monitors

# Remove stanzas in-place
collection1 -= collection1.filter(name=re.compile(r'.*-test$'))  # Remove all test objects

# Add individual stanza
new_pool_config = """
ltm pool /Common/new-pool {
    members {
        /Common/10.0.0.1:80 {
            address 10.0.0.1
        }
    }
}
"""
new_stanza_collection = StanzaCollection.from_config(new_pool_config)
collection1 += new_stanza_collection  # Note: must add as list/collection, not individual stanza
```

**Renaming Objects:**

```python
# Rename a stanza by removing, modifying, and re-adding
vs_to_rename = collection1['ltm virtual /Common/old-name']

# Remove from collection
collection1 -= [vs_to_rename]

# Modify the name (this changes full_path automatically)
vs_to_rename.name = '/Common/new-name'

# Update any references in the config_lines
vs_to_rename.find_and_replace('/Common/old-name', '/Common/new-name')

# Add back to collection (operation is logged in stanza's change history)
collection1 += [vs_to_rename]

# Verify the rename
assert 'ltm virtual /Common/new-name' in collection1
assert 'ltm virtual /Common/old-name' not in collection1
```

**Selective Merging:**

```python
# Merge only specific object types from another collection
source_collection = StanzaCollection.from_config(source_config)
target_collection = StanzaCollection.from_config(target_config)

# Add only pools and virtual servers from source
pools_and_vs = source_collection.filter(prefix=('ltm', 'pool'))
pools_and_vs += source_collection.filter(prefix=('ltm', 'virtual'))

target_collection += pools_and_vs

# Remove outdated objects before adding new ones
old_profiles = target_collection.filter(name=re.compile(r'.*-v1$'))
target_collection -= old_profiles

new_profiles = source_collection.filter(name=re.compile(r'.*-v2$'))
target_collection += new_profiles
```

**Key Points:**

- **Operators create new collections**: `+` and `-` return new collections without modifying originals
- **In-place operators modify**: `+=` and `-=` modify the existing collection
- **Operations are logged**: When stanzas are added to a collection, the operation is recorded in the stanza's change history
- **Always use lists/collections**: When adding/removing, wrap individual stanzas in a list or use collections
- **Automatic validation**: Collections prevent duplicate stanzas (same full_path) from being added

This approach enables powerful configuration manipulation workflows while maintaining a complete audit trail of changes.

### Dependency Analysis

The library automatically discovers relationships between F5 objects:

```python
# Find all objects a virtual server depends on
vs_stanzas = collection.filter(prefix=("ltm", "virtual"), name="my-vs")
dependencies = collection.get_related_stanzas(vs_stanzas.stanzas, 'dependencies')

# Find all objects that depend on a pool, e.g virtual servers
pool_stanzas = collection.filter(prefix=("ltm", "pool"), name="my-pool")
dependents = collection.get_related_stanzas(pool_stanzas.stanzas, 'dependents')
```

### iRule Dependency Detection

The library includes intelligent iRule parsing that breaks down Tcl code to detect hidden dependencies that would otherwise be missed:

```python
# iRules often contain hardcoded references to F5 objects
irule = collection['ltm rule /Common/my-irule']

# The parser automatically detects references to pools, data groups, etc.
dependencies = irule.get_dependencies()
# or dependencies = irule.get_dependencies(collection) # Call with collection object if not initialised already.
# or dependencies = irule.get_dependencies(collection, force_rediscover=True) # Call with collection object and force_rediscover=True to force rediscovery with collection object as the scope.
print(f"iRule references: {dependencies}")

# Find all data groups referenced in iRules
irule_stanzas = collection.filter(prefix=("ltm", "rule"))
all_irule_deps = collection.get_related_stanzas(irule_stanzas.stanzas, 'dependencies')
data_groups = all_irule_deps.filter(prefix=("ltm", "data-group"))
```

The iRule parser:
- **Tokenises Tcl Code**: Breaks iRule content into individual words and tokens
- **Scoped Object Detection**: Searches for object references across prioritised F5 scopes:
  - Data groups (`ltm data-group`)
  - Pools (`ltm pool`)
  - Virtual servers (`ltm virtual`)
  - Nodes (`ltm node`)
  - Monitors (`ltm monitor`)
  - Profiles (`ltm profile`)
  - Other iRules (`ltm rule`)
  - System files (`sys file`)
- **Partition-Aware Resolution**: Automatically applies partition context to unqualified object names
- **Hidden Dependency Discovery**: Finds object references that traditional parsing would miss

This is particularly valuable for:
- Discovering which pools or data groups are actually used by iRules
- Finding orphaned objects that appear unused but are referenced in code
- Understanding the complete dependency chain for applications that rely heavily on iRule logic
- Migration planning when moving configurations between environments

### Network Dependency Mapping

The library provides sophisticated network topology analysis, automatically discovering IP-based dependencies from virtual servers down to physical interfaces:

```python
# Map complete network topology for a virtual server
vs = collection['ltm virtual /Common/web-server']

# Get all network dependencies (routes, self IPs, VLANs, interfaces)
network_deps = collection.get_related_stanzas([vs])

# Find which VLANs are used by a virtual server
vlans = collection.get_related_stanzas([vs], 'dependencies').filter(prefix=("net", "vlan"))
print(f"VLANs used by {vs.name}: {[v.name for v in vlans]}")

# Find which physical interfaces support a virtual server
interfaces = collection.get_related_stanzas([vs], 'dependencies').filter(prefix=("net", "interface"))
print(f"Interfaces used by {vs.name}: {[i.name for i in interfaces]}")
```

The network dependency resolution works through multiple layers:
- **Virtual Servers/Pools/SNATs** → Routes (based on destination/member IP addresses)
- **Routes** → Self IPs (based on gateway IP and route domains)
- **Self IPs** → VLANs (based on VLAN assignments)
- **VLANs** → Physical Interfaces (based on interface memberships)

This allows you to answer questions like:
- Which physical interfaces does a virtual server ultimately depend on?
- What network path does traffic take for a specific application?
- Which VLANs are required for a particular service to function?

```python
# Example: Complete network path analysis
vs = collection['ltm virtual /Common/critical-app']

# Get the complete dependency chain
all_deps = collection.get_related_stanzas([vs], 'dependencies')

# Separate by network layer
routes = all_deps.filter(prefix=("net", "route"))
selfips = all_deps.filter(prefix=("net", "self"))
vlans = all_deps.filter(prefix=("net", "vlan"))
interfaces = all_deps.filter(prefix=("net", "interface"))

print(f"Network path for {vs.name}:")
print(f"  Routes: {[r.name for r in routes]}")
print(f"  Self IPs: {[s.name for s in selfips]}")
print(f"  VLANs: {[v.name for v in vlans]}")
print(f"  Interfaces: {[i.name for i in interfaces]}")
```

### Change Tracking

All modifications are automatically logged with detailed change records:

```python
# Make changes with automatic logging
vs.find_and_replace('192.168.1.100', '10.0.1.100')

# Directly modify the config_lines attribute using Python list operation
# These changes are intercepted and logged as well.
vs.config_lines = [x.replace('dev', 'prod') for x in vs.config_lines]
del vs.config_lines[:-2]

# View change history
for change in vs._changes:
    print(f"Change {change.change_id}: {change.change_type} at {change.timestamp}")
```

### Advanced Filtering

Combine multiple filter criteria for precise queries:

```python
# Complex filtering
results = collection.filter(
    prefix=("ltm", "virtual"),
    name=re.compile(r'prod-.*'),
    content="ssl",
    destination="443"
)

# Custom parsed config filtering
ssl_vs = collection.filter(
    prefix=("ltm", "virtual"),
    **{"profiles": "clientssl"}
)
```

## Practical Use Cases

### Configuration Manipulation and Deployment

A common operational task is creating new configurations based on existing ones with specific modifications. The library provides powerful tools for configuration manipulation with automatic change logging:

```python
from f5_config_parser.collection import StanzaCollection

# Load existing configuration
with open('input/bigip.conf') as f:
    collection = StanzaCollection.from_config(f.read(), initialise_dependencies=False)

# Find and modify existing objects
pools = collection.filter(prefix=('ltm', 'pool'), content='10.51.33.222')
vip = collection.filter(prefix=('ltm', 'virtual'), name='/NON-PROD/WebApp-HTTP')

# Direct manipulation of config lines (automatically logged)
del pools.stanzas[0].config_lines[10:22]  # Remove specific lines

# Create new configurations by string manipulation
new_vip_config = str(vip[0]).replace('/NON-PROD/WebApp-HTTP', '/NON-PROD/WebApp-HTTPS')
new_pool_config = str(pools[0]).replace('/NON-PROD/Pool-WebApp-HTTP', '/NON-PROD/Pool-WebApp-HTTPS')

# Parse the new configurations into a fresh collection
new_config = StanzaCollection.from_config(new_vip_config + new_pool_config)

# Apply systematic changes across all objects
for stanza in new_config:
    if stanza.prefix[1] == 'virtual':
        # Update pool references
        stanza.find_and_replace(
            'pool /NON-PROD/Pool-WebApp-HTTP', 
            'pool /NON-PROD/Pool-WebApp-HTTPS', 
            match_type='whole_line'
        )
        
        # Insert new configuration lines at specific positions
        stanza.config_lines[13:13] = [
            '     /NON-PROD/webapp-test.example.com {',
            '        context clientside',
            '      }'
        ]
    
    # Apply changes to all objects
    stanza.find_and_replace(':80', ':443', match_type='substring')
    
    if stanza.prefix[1] == 'pool':
        # Remove unwanted configuration lines
        stanza.config_lines = [line for line in stanza.config_lines 
                              if 'priority-group' not in line]

# Output the complete modified configuration ready for deployment
print(new_config)
```

**Key Benefits of This Approach:**

- **Automatic Change Logging**: All modifications are tracked with timestamps and change IDs
- **Flexible Line Manipulation**: Direct access to configuration lines as standard Python lists
- **Batch Operations**: Apply changes across multiple objects systematically
- **String-Based Templating**: Create new configurations through string replacement
- **Grouped Output**: Print complete configuration blocks ready for F5 deployment
- **Type-Aware Processing**: Different logic for different object types (virtual servers vs pools)

**Change Tracking Example:**
```python
# After making changes, view the modification history
for stanza in new_config:
    if stanza._changes:
        print(f"Changes to {stanza.full_path}:")
        for change in stanza._changes:
            print(f"  {change.timestamp}: {change.change_type}")
```

This approach is particularly valuable for:
- **Environment Promotions**: Converting test configurations for production deployment
- **Bulk Modifications**: Applying consistent changes across multiple similar objects
- **Configuration Templates**: Creating standardised configurations from existing examples
- **Migration Tasks**: Adapting configurations for new infrastructure

### Virtual Server Deletion with Safe Dependency Removal

When decommissioning virtual servers, it's critical to identify and remove only the dependencies that are exclusively used by those virtual servers, while preserving shared resources. The library provides tools to build a safe, ordered deletion plan that respects dependency relationships:

```python
from f5_config_parser.dependency_resolver import build_waves_structure
from f5_config_parser.collection import StanzaCollection

# Load the F5 configuration
with open('f5_scf_config.txt') as f:
    all_stanzas = StanzaCollection.from_config(f.read())

# Identify all virtual servers
all_vip_stanzas = all_stanzas.filter(prefix=('ltm', 'virtual'))

# Select virtual servers to delete
vips_stanzas_to_delete = all_vip_stanzas.filter(name='vs-api-gateway')
vips_stanzas_to_delete += all_vip_stanzas.filter(name='vs-app-custom')

# Find all dependencies of VIPs to delete
vips_stanzas_to_delete_deps = all_stanzas.get_related_stanzas(vips_stanzas_to_delete)

# Find all dependencies of VIPs to keep
vips_stanzas_to_keep_deps = all_stanzas.get_related_stanzas(
    all_vip_stanzas - vips_stanzas_to_delete
)

# Calculate objects that can be safely deleted (not used by remaining VIPs)
vips_stanzas_to_delete_deps = vips_stanzas_to_delete_deps - vips_stanzas_to_keep_deps

# Build deletion waves - objects that can be deleted in parallel
waves = build_waves_structure(vips_stanzas_to_delete_deps)

# Generate deletion plan
with open('vs_delete_plan.txt', 'w') as f:
    f.write('Config items to remove (TODO: convert to tmsh cmds)\n\n')
    for wave_num, (wave, stanzas) in enumerate(waves.items(), 1):
        f.write(f'Wave {wave_num}\n')
        for stanza in stanzas:
            f.write(f'Remove: {stanza.full_path}\n')
        f.write('\n')
```

**Key Features of This Approach:**

- **Safe Dependency Identification**: Automatically identifies dependencies that are exclusively used by the virtual servers being deleted
- **Shared Resource Protection**: Preserves any dependencies that are used by other virtual servers
- **Ordered Deletion Waves**: Builds a deletion plan in waves, where each wave contains objects that can be safely deleted in parallel
- **Dependency Tree Navigation**: Works down the dependency tree systematically, ensuring objects are deleted in the correct order
- **Audit Trail**: Generates a clear deletion plan that can be reviewed before execution

**Example Output:**
```
Config items to remove (TODO: convert to tmsh cmds)

Wave 1
Remove: ltm virtual /Common/vs-api-gateway
Remove: ltm virtual /Common/vs-app-custom

Wave 2
Remove: ltm pool /Common/pool-api-gateway
Remove: ltm profile client-ssl /Common/profile-custom-ssl
Remove: ltm rule /Common/irule-app-custom

Wave 3
Remove: ltm node /Common/10.1.1.100
Remove: ltm node /Common/10.1.1.101
Remove: ltm monitor https /Common/monitor-api-health
```

This approach is particularly valuable for:
- **Service Decommissioning**: Safely removing applications and all their unique dependencies
- **Configuration Cleanup**: Identifying and removing orphaned objects after virtual server deletion
- **Change Planning**: Creating reviewable deletion plans before making production changes
- **Preventing Outages**: Ensuring shared resources aren't accidentally deleted

### Orphaned Configuration Cleanup

Over time, F5 configurations can accumulate orphaned objects - pools, profiles, certificates, and other resources that are no longer referenced by any virtual server. The library can identify these orphaned objects and create a safe deletion plan that includes all unused dependencies, including SSL certificates and their issuing CAs:

```python
from f5_config_parser.dependency_resolver import build_waves_structure
from f5_config_parser.collection import StanzaCollection
from f5_config_parser.certificates.certificate_loader import load_certificates_from_tar

# Load F5 configuration
with open('bigip.conf') as f:
    all_stanzas = StanzaCollection.from_config(f.read())

# Optional: Include certificates for complete cleanup
certificates = load_certificates_from_tar('f5_backup.tar')
all_stanzas += certificates

# Focus on LTM objects (or expand to include other modules)
ltm_stanzas = all_stanzas.filter(prefix=('ltm',))
all_vip_stanzas = ltm_stanzas.filter(prefix=('ltm', 'virtual'))

# Find all objects used by virtual servers
used_stanzas = all_stanzas.get_related_stanzas(all_vip_stanzas)

# Identify orphaned objects (excluding virtual addresses which are auto-managed)
orphaned_stanzas = (ltm_stanzas - 
                    used_stanzas - 
                    ltm_stanzas.filter(prefix=('ltm', 'virtual-address')))

# Build deletion waves for safe removal
waves = build_waves_structure(orphaned_stanzas)

# Generate cleanup plan
with open('orphaned_delete_plan.txt', 'w') as f:
    f.write('Orphaned config items to remove\n\n')
    for wave_num, (wave, stanzas) in enumerate(waves.items(), 1):
        f.write(f'Wave {wave_num}\n')
        for stanza in stanzas:
            f.write(f'Remove: {stanza.full_path}\n')
        f.write('\n')

# Analyse what's being cleaned up
print(f"Found {len(orphaned_stanzas)} orphaned objects")
by_type = {}
for stanza in orphaned_stanzas:
    obj_type = ' '.join(stanza.prefix)
    by_type[obj_type] = by_type.get(obj_type, 0) + 1

print("Orphaned objects by type:")
for obj_type, count in sorted(by_type.items()):
    print(f"  {obj_type}: {count}")
```

**Extended Example with Certificate Cleanup:**

```python
# For complete cleanup including certificates and their chains
from f5_config_parser.certificates.certificate_loader import load_certificates_from_tar

# Load configuration and certificates
all_stanzas = StanzaCollection.from_config(config_text)
certificates = load_certificates_from_tar('f5_backup.tar')
all_stanzas += certificates

# Find all objects used by virtual servers (including certificates via SSL profiles)
all_vip_stanzas = all_stanzas.filter(prefix=('ltm', 'virtual'))
used_stanzas = all_stanzas.get_related_stanzas(all_vip_stanzas)

# Identify all orphaned objects across all modules
orphaned_stanzas = all_stanzas - used_stanzas

# Filter to specific types if needed
orphaned_certs = orphaned_stanzas.filter(prefix=('certificate', 'object'))
orphaned_pools = orphaned_stanzas.filter(prefix=('ltm', 'pool'))
orphaned_profiles = orphaned_stanzas.filter(prefix=('ltm', 'profile'))

# Check for orphaned certificate chains
for cert in orphaned_certs:
    if cert.is_ca:
        print(f"Orphaned CA certificate: {cert.filename}")
        # Check if any non-orphaned certs depend on this CA
        active_certs = used_stanzas.filter(prefix=('certificate', 'object'))
        if any(c.aki == cert.ski for c in active_certs if not c.is_ca):
            print(f"  WARNING: Still used as issuer for active certificates")
```

**Key Benefits:**

- **Comprehensive Cleanup**: Identifies all unused objects including pools, profiles, monitors, iRules, and certificates
- **Certificate Chain Awareness**: Can identify orphaned certificates and their issuing CAs
- **Safe Deletion Order**: Generates waves ensuring dependencies are removed in the correct sequence
- **Selective Filtering**: Can focus on specific object types or modules (LTM, GTM, etc.)
- **Audit Before Action**: Provides detailed analysis of what will be removed before execution

**Example Output:**
```
Orphaned config items to remove

Wave 1
Remove: ltm pool /Common/old-app-pool
Remove: ltm rule /Common/deprecated-irule
Remove: ltm profile tcp /Common/unused-tcp-profile

Wave 2
Remove: ltm monitor http /Common/old-health-check
Remove: ltm profile client-ssl /Common/expired-ssl-profile

Wave 3
Remove: ltm node /Common/10.0.0.50
Remove: certificate object /Common/expired-cert.crt
Remove: certificate object /Common/old-ca-cert.crt
```

This approach is particularly valuable for:
- **Configuration Hygiene**: Regular cleanup of unused objects to maintain manageable configs
- **Security Compliance**: Removing expired certificates and unused SSL profiles
- **Performance Optimisation**: Reducing configuration size and complexity
- **Pre-Migration Cleanup**: Simplifying configurations before migrating to new devices
- **License Optimisation**: Identifying unused licensed features or modules

### Finding Virtual Servers by Profile Type

Virtual server configurations reference profiles by name without specifying the profile type, making it challenging to identify which virtual servers use specific types of profiles (HTTP, TCP, SSL, etc.). The library enables simple cross-referencing to discover these relationships:

```python
from f5_config_parser.collection import StanzaCollection

# Load configuration
with open('f5_config.txt') as f:
    all_stanzas = StanzaCollection.from_config(f.read())

# Get all virtual servers and HTTP profiles
all_vip_stanzas = all_stanzas.filter(prefix=('ltm', 'virtual'))
all_http_profiles = all_stanzas.filter(prefix=('ltm', 'profile', 'http'))

# Find virtual servers using HTTP profiles
for vs_stanza in all_vip_stanzas:
    for profile in vs_stanza.parsed_config['profiles'].keys():
        if f'ltm profile http {profile}' in all_http_profiles:
            print(f"{vs_stanza.name} uses HTTP profile: {profile}")
```

**Extending to Multiple Profile Types:**

```python
# Check for different profile types
profile_types = {
    'http': all_stanzas.filter(prefix=('ltm', 'profile', 'http')),
    'tcp': all_stanzas.filter(prefix=('ltm', 'profile', 'tcp')),
    'client-ssl': all_stanzas.filter(prefix=('ltm', 'profile', 'client-ssl')),
    'server-ssl': all_stanzas.filter(prefix=('ltm', 'profile', 'server-ssl')),
    'persistence': all_stanzas.filter(prefix=('ltm', 'persistence'))
}

# Map virtual servers to their profile types
vs_profile_mapping = {}
for vs_stanza in all_vip_stanzas:
    vs_profile_mapping[vs_stanza.name] = []
    
    for profile in vs_stanza.parsed_config.get('profiles', {}).keys():
        for profile_type, profile_collection in profile_types.items():
            if f'ltm profile {profile_type} {profile}' in profile_collection:
                vs_profile_mapping[vs_stanza.name].append((profile_type, profile))
                break  # Found the type, move to next profile

# Find all virtual servers with SSL profiles
ssl_enabled_vs = [vs for vs, profiles in vs_profile_mapping.items() 
                   if any(ptype in ['client-ssl', 'server-ssl'] 
                          for ptype, _ in profiles)]
print(f"Virtual servers with SSL: {ssl_enabled_vs}")
```

**Key Benefits:**

- **Profile Type Discovery**: Identify which virtual servers use specific profile types without parsing the VS config manually
- **Cross-Reference Validation**: Verify that referenced profiles actually exist in the configuration
- **Security Auditing**: Quickly find all SSL-enabled virtual servers or those missing security profiles
- **Migration Planning**: Understand profile dependencies when moving virtual servers between devices
- **Simple String Matching**: Uses the collection's `in` operator with full_path strings for efficient lookups

This approach is particularly valuable for:
- **Security Reviews**: Finding virtual servers without WAF profiles or with outdated SSL profiles
- **Performance Tuning**: Identifying virtual servers using specific TCP or HTTP profiles
- **Compliance Auditing**: Ensuring all external-facing virtual servers have required security profiles
- **Profile Cleanup**: Finding which virtual servers would be affected before modifying or removing profiles

### Configuration Drift Detection Between F5 Devices

Comparing configurations between F5 devices is straightforward using Python's built-in set operations. The library's design allows powerful analysis with minimal code by leveraging the object's `full_path` for identification and `config_lines` for comparison:

```python
from f5_config_parser.collection import StanzaCollection

# Load configurations from two different F5 devices
with open('device1_config.txt') as f:
    device1_collection = StanzaCollection.from_config(f.read(),
                                                      initialise=False)

with open('device2_config.txt') as f:
    device2_collection = StanzaCollection.from_config(f.read(),
                                                      initialise=False)

# Extract sets of full_path strings to find objects with matching names
device1_paths = {stanza.full_path for stanza in device1_collection}
device2_paths = {stanza.full_path for stanza in device2_collection}

# Find objects that exist on both devices (by name)
common_paths = device1_paths & device2_paths

device1_set = set(device1_collection)
device2_set = set(device2_collection)

# Intersection of device1 and device2 to identify config items that have the same name and same configuration
common_stanzas = device1_set & device2_set

# Convert to strings to allow comparison with the common_stanzas set
common_stanzas_paths = {stanza.full_path for stanza in common_stanzas}

# Find objects that exist on both devices under the same name but have differing config
differing_stanzas = common_paths - common_stanzas_paths
differing_stanzas_collection_1 = StanzaCollection([device1_collection[x] for x in differing_stanzas])
differing_stanzas_collection_2 = StanzaCollection([device2_collection[x] for x in differing_stanzas])

# Quick and dirty comparison
for path in differing_stanzas:
    diff = set(device1_collection[path].config_lines) ^ set(device2_collection[path].config_lines)
    print(f"{path}: {diff}")
```

**Key Insights:**

- **Minimal Code, Maximum Power**: Just a few lines of standard Python reveals configuration drift
- **Set Operations on Objects**: The library's objects work seamlessly with Python's set operations
- **Two-Level Comparison**:
  - Object names compared using `full_path` strings
  - Object equality uses both `full_path` and `config_lines` (via the `__eq__` method)
- **Direct Access**: `config_lines` is a simple list - manipulate it with any Python list/set operations
- **Symmetric Difference (`^`)**: Shows all lines that differ between the two configurations

**Example Output:**
```
ltm pool /Common/web-pool: {'min-active-members 2', 'min-active-members 1'}
ltm virtual /Common/app-vip: {'rate-limit 1000', 'rate-limit 500', 'description "Production"', 'description "Development"'}
ltm profile tcp /Common/custom-tcp: {'idle-timeout 300', 'idle-timeout 600'}
```

This approach is particularly valuable for:
- **Migration Projects**: Essential for keeping old and new F5 configurations in sync during lengthy migrations
- **Continuous Sync Verification**: Ensure configurations remain aligned as changes occur on the source device during migration
- **Quick Audits**: Rapidly identify configuration differences between HA pairs
- **Change Verification**: Confirm that changes were applied correctly across devices
- **Troubleshooting**: Find configuration discrepancies that might cause different behaviour
- **Pre-Sync Analysis**: Understand what will change before synchronising configurations

**Migration Use Case:**

During F5 migrations, configurations often need to be copied from old to new devices while production changes continue on the source. This simple comparison approach enables:
- **Baseline Verification**: Confirm initial configuration copy was complete
- **Drift Monitoring**: Regularly check for new changes on the source device during the migration window
- **Selective Updates**: Identify and copy only the changed objects to the new device
- **Final Validation**: Ensure complete configuration parity before cutover

The beauty of this approach is its simplicity - no complex APIs or methods to learn, just Python sets and the straightforward `config_lines` attribute.

### Finding Pool Members with Specific Priority Groups

When working with complex F5 configurations that have nested structures and varying attribute presence, you may need more granular control than basic filtering methods provide. This verbose filtering approach is particularly useful when you need to drill down into nested configuration objects (like pool members), handle optional or missing attributes gracefully, or combine multiple filtering criteria across different levels of the configuration hierarchy. You have the flexibility to use either traditional loops with exception handling for robust error handling, or list comprehensions for cleaner code when you're confident about the data structure consistency.

```python
from f5_config_parser.collection import StanzaCollection

with open("f5_config.txt") as f:
    collection = StanzaCollection.from_config(f.read(), initialise_dependencies=False)

# Find all pools containing a specific IP
pools = collection.filter(prefix=('ltm', 'pool'), content='10.51.0.127')

# Filter pools where this IP has priority-group 1
pools_with_priority_1 = []
for pool in pools:
    for member, member_config in pool.parsed_config['members'].items():
        try:
            if member_config['address'] == '10.51.0.127' and member_config['priority-group'] == '1':
                pools_with_priority_1.append(pool)
        except KeyError:
            pass  # Member doesn't have priority-group configured

# Use set difference to find pools with this member but NOT priority-group 1
pools_without_priority = set(pools) - set(pools_with_priority_1)

# Find virtual servers that depend on the priority-group 1 pools
# Dependency discovery will be triggered here if not already initialised
matched_virtuals = collection.get_related_stanzas(
    pools_with_priority_1, 
    relation_type='dependents'
).filter(prefix=('ltm', 'virtual'))
```

**Alternative Method Using config_lines:**

When the parsed configuration attributes don't exist or you need to work directly with the raw configuration text, you can analyse the configuration lines directly:

```python
pools = collection.filter(prefix=('ltm', 'pool'), content='10.51.0.127')

for pool in pools:
    for (line1, line2) in zip(pool.config_lines, pool.config_lines[1:]):
        if '10.51.0.127' in line1 and 'priority-group 1' in line2:
            print(f'Pool {pool.name} is using 10.51.0.127 as a backup member')
            break
    else:
        print(f'Pool {pool.name} is not using 10.51.0.127 as a backup member')
```

This direct line-by-line approach is useful when:
- The parsed configuration doesn't contain the attributes you need
- You want to analyse configuration patterns that don't map cleanly to dictionary structures
- Dealing with complex nested configurations where parsing may be incomplete
- Working with newer F5 features not yet fully supported by the parser

**Alternative Using List Comprehensions:**
When you know the configuration attributes exist, list comprehensions offer a cleaner approach:

```python
# If you're certain all pools have members with 'address' and 'priority-group' attributes:
pools_with_priority_1 = [
    pool for pool in pools
    if any(member_config.get('address') == '10.51.0.127' and 
           member_config.get('priority-group') == '1'
           for member_config in pool.parsed_config.get('members', {}).values())
]

# Or for finding all virtual servers with a specific profile attribute:
ssl_virtuals = [
    vs for vs in collection.filter(prefix=('ltm', 'virtual'))
    if any('clientssl' in profile_name.lower() 
           for profile_name in vs.parsed_config.get('profiles', {}).keys())
]
```

The choice between loops with exception handling, direct config_lines analysis, and list comprehensions depends on your data's consistency and whether missing attributes are expected.

### Complex Filtering with Set Operations on Single Collections

When the built-in filter method's simple inclusion matching isn't sufficient for your needs, set operations provide a powerful way to create compound filtering logic on a single collection. This approach is essential when you need AND, OR, or NOT operations across different filtering criteria, since the filter method doesn't natively support these compound operations. You can extract multiple filtered sets based on different criteria and then use set operations to combine them in sophisticated ways.

```python
from f5_config_parser.collection import StanzaCollection

with open("f5_config.txt") as f:
    collection = StanzaCollection.from_config(f.read(), initialise_dependencies=False)

# Get base sets using different filter criteria
ssl_virtuals = set(collection.filter(prefix=('ltm', 'virtual'), content='clientssl'))
port_80_virtuals = set(collection.filter(prefix=('ltm', 'virtual'), content=':80'))
port_443_virtuals = set(collection.filter(prefix=('ltm', 'virtual'), content=':443'))
dmz_virtuals = set(collection.filter(prefix=('ltm', 'virtual'), content='dmz'))

# AND operation: SSL virtuals that are also in DMZ (intersection)
ssl_and_dmz = ssl_virtuals & dmz_virtuals

# OR operation: virtuals on either port 80 OR port 443 (union)
web_ports = port_80_virtuals | port_443_virtuals

# NOT operation: DMZ virtuals that are NOT SSL-enabled (difference)  
dmz_not_ssl = dmz_virtuals - ssl_virtuals

# Complex compound: (SSL AND DMZ) OR (port 80 AND NOT DMZ)
complex_filter = (ssl_virtuals & dmz_virtuals) | (port_80_virtuals - dmz_virtuals)

# Get additional filter sets for more complex operations
persistence_virtuals = set(collection.filter(prefix=('ltm', 'virtual'), content='persist'))
irules_virtuals = set(collection.filter(prefix=('ltm', 'virtual'), content='rules'))

# Multiple AND conditions: SSL AND persistence AND iRules
fully_featured = ssl_virtuals & persistence_virtuals & irules_virtuals

# Multiple NOT conditions: virtuals with NO SSL, NO persistence, NO iRules
basic_virtuals = set(collection.filter(prefix=('ltm', 'virtual'))) - ssl_virtuals - persistence_virtuals - irules_virtuals

# Complex nested logic: (SSL OR persistence) AND NOT (port 80 OR DMZ)
advanced_secure = (ssl_virtuals | persistence_virtuals) - (port_80_virtuals | dmz_virtuals)

print(f"SSL and DMZ virtuals: {len(ssl_and_dmz)}")
print(f"Web port virtuals: {len(web_ports)}")  
print(f"DMZ non-SSL virtuals: {len(dmz_not_ssl)}")
print(f"Basic virtuals (no features): {len(basic_virtuals)}")
```

This example demonstrates:
* Using intersection (&) for AND logic across multiple criteria
* Using union (|) for OR logic to combine different filter results
* Using difference (-) for NOT logic to exclude certain configurations
* Chaining multiple set operations for complex compound filtering
* Building sophisticated filtering logic that's impossible with single filter calls

**Alternative Using Attribute-Based Set Construction:**
When you need to filter on parsed configuration attributes rather than content matching:

```python
# Build sets based on parsed configuration attributes
all_virtuals = collection.filter(prefix=('ltm', 'virtual'))

# Create sets using comprehensions on parsed attributes
high_port_virtuals = {
    vs for vs in all_virtuals
    if vs.parsed_config.get('destination', '').split(':')[-1].isdigit()
    and int(vs.parsed_config.get('destination', '').split(':')[-1]) > 8000
}

pool_virtuals = {
    vs for vs in all_virtuals 
    if vs.parsed_config.get('pool')
}

profile_virtuals = {
    vs for vs in all_virtuals
    if vs.parsed_config.get('profiles')
}

# Compound operations on attribute-based sets
# Virtuals with pools AND profiles but NOT on high ports
standard_featured = (pool_virtuals & profile_virtuals) - high_port_virtuals

# Virtuals with pools OR profiles (but not necessarily both)
any_features = pool_virtuals | profile_virtuals

# Get all pools and create filter sets
all_pools = collection.filter(prefix=('ltm', 'pool'))

monitor_pools = {
    pool for pool in all_pools
    if pool.parsed_config.get('monitor')
}

member_pools = {
    pool for pool in all_pools  
    if pool.parsed_config.get('members')
}

# Complex pool filtering: pools with members AND monitors but NOT containing specific IPs
production_ready_pools = (member_pools & monitor_pools) - {
    pool for pool in member_pools
    if any('192.168.' in member for member in pool.parsed_config.get('members', {}))
}
```

Set operations provide the compound filtering capabilities that the basic filter method lacks, allowing you to express complex configuration queries with mathematical precision and clarity.

### Finding Which Network Objects Contain Pool Members

When you need to determine exactly which self IP network objects contain specific pool members, the get_related_stanzas method provides a starting point by finding related network objects, but it doesn't tell you which specific networks match individual pool members. To drill down and identify precise network containment relationships, you can use the built-in contains functionality by testing if a pool member's IP_ID is within each network object. This approach is essential for network troubleshooting, security analysis, and validating that pool members are accessible through the correct network interfaces.

```python
from f5_config_parser.collection import StanzaCollection

with open("f5_config.txt") as f:
    collection = StanzaCollection.from_config(f.read(), initialise_dependencies=False)

# Find pools containing a specific IP and get all network objects
pools = collection.filter(prefix=('ltm', 'pool'), content='10.51.0.127')
all_net = collection.filter(prefix=('net', 'self'))

# Use dependency discovery to find related network objects
matched_net_dependencies = collection.get_related_stanzas(pools).filter(prefix=('net', 'self'))
non_matched_net_dependencies = all_net - matched_net_dependencies

# Iterate through pool members and extract IP_ID values for precise matching
for pool in pools:
    print(f"Pool: {pool.name}")
    for member_name, member_config in pool.parsed_config.get('members', {}).items():
        member_ip_id = member_config['ip_rd']
        print(f"  Member: {member_name}, IP_ID: {member_ip_id}")
        
        # Test against matched net dependencies
        print("  Matched net dependencies:")
        for net_obj in matched_net_dependencies:
            result = member_ip_id in net_obj
            print(f"    {net_obj.name}: {result}")
        
        # Test against non-matched net dependencies  
        print("  Non-matched net dependencies:")
        for net_obj in non_matched_net_dependencies:
            result = member_ip_id in net_obj
            print(f"    {net_obj.name}: {result}")
        print()
```

This example demonstrates:
* Using get_related_stanzas to identify potentially related network objects
* Extracting the ip_rd attribute from pool member configurations
* Using the `in` operator to test network containment for each member
* Comparing results between dependency-matched and non-matched network objects
* Precise identification of which network objects actually contain specific pool members

**Alternative for Comprehensive Network Analysis:**
When you need to analyse all pool members across multiple pools and their network relationships:

```python
# Analyse network containment across all pools
all_pools = collection.filter(prefix=('ltm', 'pool'))
all_self_ips = collection.filter(prefix=('net', 'self'))

network_analysis = {}

for pool in all_pools:
    pool_networks = []
    
    for member_name, member_config in pool.parsed_config.get('members', {}).items():
        member_ip_id = member_config['ip_rd']
        
        # Find which networks contain this member
        containing_networks = [
            net_obj.name for net_obj in all_self_ips 
            if member_ip_id in net_obj
        ]
        
        pool_networks.append({
            'member': member_name,
            'address': member_config['address'],
            'ip_id': member_ip_id,
            'networks': containing_networks
        })
    
    network_analysis[pool.name] = pool_networks

# Display comprehensive analysis
for pool_name, members in network_analysis.items():
    print(f"\nPool: {pool_name}")
    for member in members:
        if member['networks']:
            print(f"  {member['member']} is in networks: {', '.join(member['networks'])}")
        else:
            print(f"  {member['member']} is not contained in any self IP networks")

# Find orphaned members (not in any self IP network)
orphaned_members = [
    (pool_name, member) 
    for pool_name, members in network_analysis.items()
    for member in members
    if not member['networks']
]

if orphaned_members:
    print(f"\nFound {len(orphaned_members)} orphaned pool members:")
    for pool_name, member in orphaned_members:
        print(f"  {member['member']} in {pool_name}")
```

While get_related_stanzas identifies potential network relationships through dependency analysis, this direct containment testing approach provides definitive answers about which specific network objects actually contain each pool member.

## Outputting Configuration

The library makes it simple to output F5 configuration in its original format by calling `str()` on collections or individual stanzas:

```python
from f5_config_parser.collection import StanzaCollection

# Load configuration
with open('f5_config.txt') as f:
    collection = StanzaCollection.from_config(f.read())

# Output entire collection
print(collection)  # Prints all stanzas in the collection

# Output individual stanza
vs = collection['ltm virtual /Common/my-virtual-server']
print(vs)  # Prints just this virtual server's configuration

# Write to file
with open('output.conf', 'w') as f:
    f.write(str(collection))  # Write entire collection
    # Or for a filtered subset:
    pools = collection.filter(prefix=('ltm', 'pool'))
    f.write(str(pools))  # Write only pool configurations

# Get configuration as string for further processing
config_text = str(collection)  # Returns the configuration as a string
single_vs_text = str(vs)  # Returns single stanza configuration as a string
```

This is particularly useful for:
- Generating deployment scripts with modified configurations
- Creating backups of specific object types
- Building configuration templates from existing objects

## Performance Considerations
When working with large F5 configurations, consider these performance optimisations:

### Dependency Caching (Recommended Default)
The default configuration enables automatic dependency discovery with manual cache saving for optimal performance:
```python
# Recommended: Use defaults for automatic discovery with manual cache saving
collection = StanzaCollection.from_config(
    config_text,
    initialise=True,           # Default: True - IP/RD resolution and Dependency discovery for all stanzas, Consider setting this to false if you know you are going to add in additional objects and reinitialise and save later.
)
# Save cache after initial dependency discovery
collection.save_dependency_cache()
```
**Benefits of manual cache saving:**
- First run discovers dependencies, you save them to cache file when ready
- Subsequent runs on the same config load dependencies from cache (much faster)
- Control when cache is saved after adding new objects (like certificates)
- No performance penalty after initial discovery and cache save

### Flexible Dependency Access
The dependency API automatically handles both cached and uncached states:
```python
# Works efficiently regardless of cache state
for stanza in collection:
    deps = stanza.get_dependencies(collection)  # Auto-discovers if needed, uses cache if available
    
# Access cached dependencies without collection parameter
deps = stanza.get_dependencies()  # Returns cached results

# Force refresh when config scope changes
deps = stanza.get_dependencies(collection, force_rediscover=True)
```

### Lazy Initialisation (Special Cases)
Only disable dependency initialisation for specific performance-critical scenarios, or when you will be adding additional objects immediately and reinitialising and saving the cache after that. Will:
```python
# Skip dependency initialisation for faster loading (not recommended for most cases)
collection = StanzaCollection.from_config(
    config_text, 
    initialise=False,
)

# Manual dependency resolution when needed
vs = collection.filter(prefix=("ltm", "virtual"), name="my-vs")[0]
vs_deps = vs.get_dependencies(collection)  # Discovers on first call
```

### Selective Dependency Resolution
For very large configurations, you can work with subsets:
```python
# Load without automatic dependency resolution (if needed)
collection = StanzaCollection.from_config(
    config_text, 
    initialise_dependencies=False,
)

# Resolve dependencies only for specific virtual servers
important_vs = collection.filter(name=re.compile(r'prod-.*'))
for vs in important_vs:
    vs_deps = vs.get_dependencies(collection)  # Efficient mixed-state processing
```

### Adding Objects After Initial Load
When you add stanzas to an existing collection, you can reinitialise dependencies to include the new objects:
```python
# Load initial configuration
with open(INPUT_FILE) as f:
    all_stanzas = StanzaCollection.from_config(f.read())

# Add certificate objects from external source
certificates = load_certificates_from_tar(TAR_FILE)
all_stanzas += certificates

# Reinitialise dependencies to include certificate objects
all_stanzas.initialise_dependencies()  # Detects new objects, recalculates all dependencies

# Save updated cache with certificate dependencies
all_stanzas.save_dependency_cache()
```

**What happens during reinitialisation:**
- Cache coverage check detects the new certificate objects aren't cached
- All dependencies are recalculated (existing + new objects)
- Call save_dependency_cache() to save updated dependency data to cache
- Next program run will load all dependencies (including certificates) from cache
- SSL profiles, virtual servers, and other objects will now show certificate dependencies

### Cache File Benefits
- **First Run**: Dependencies discovered, you save to cache file with save_dependency_cache()
- **Subsequent Runs**: Dependencies loaded from cache (5-10x faster)
- **Manual Coverage Control**: You control when cache is saved after adding new objects
- **Unified Processing**: All dependency types (including iRules) cached together
- **Controlled Updates**: Cache updates when you call save_dependency_cache() after changes
 
## Error Handling and Logging

The library includes comprehensive validation and logging capabilities to ensure configuration parsing accuracy. Always validate when parsing new F5 configurations to catch potential parsing errors early.

### Configuration Validation

The `validate_scf_parsing.py` module (invoked automatically when loading a new configuration from config file or text) provides validation functions that verify the parser correctly processes your F5 configuration. This is critical when working with new or complex configurations.

### Validation Process

The validation performs three critical checks:

#### Content Reconstruction Validation
Ensures the parsed objects can accurately reconstruct the original configuration:
- Compares original configuration text with reconstructed output
- Generates detailed diff output if mismatches are found
- Raises `ValueError` with character count differences if content doesn't match

#### Heading Count Validation
Verifies all configuration stanzas were correctly identified and parsed:
- Counts stanzas by type in original configuration
- Compares with parsed object counts
- Identifies missing or extra stanzas

#### Duplicate Detection
Ensures no stanzas were incorrectly duplicated during parsing:
- Uses hash comparison to detect identical stanzas
- Raises exception if duplicate stanzas are found

### Understanding the Validation Log

The validation process creates a detailed log file, each time a configuration is loaded, `f5_config_validation.log` containing:

#### Successful Validation Log Example
```
2025-01-15 10:23:45 - validate_scf_parsing - INFO - Starting heading extraction from 15234 lines of configuration
2025-01-15 10:23:45 - validate_scf_parsing - INFO - Found 487 F5-specific headings and 487 generic headings
2025-01-15 10:23:45 - validate_scf_parsing - INFO - Categorised headings into 23 unique prefix types
2025-01-15 10:23:45 - validate_scf_parsing - INFO - Configuration content match detected 8234567891 == 8234567891
2025-01-15 10:23:45 - validate_scf_parsing - INFO - Duplicate validation passed: 487 stanzas, all unique
2025-01-15 10:23:45 - validate_scf_parsing - INFO - Starting heading count validation for 23 heading types
2025-01-15 10:23:45 - validate_scf_parsing - INFO - [VALID] Prefix 'ltm virtual' - Expected: 45, Found: 45
2025-01-15 10:23:45 - validate_scf_parsing - INFO - [VALID] Prefix 'ltm pool' - Expected: 62, Found: 62
2025-01-15 10:23:45 - validate_scf_parsing - INFO - Validation summary:
2025-01-15 10:23:45 - validate_scf_parsing - INFO -   Total expected stanzas: 487
2025-01-15 10:23:45 - validate_scf_parsing - INFO -   Total actual stanzas: 487
2025-01-15 10:23:45 - validate_scf_parsing - INFO -   Validation status: PASSED
2025-01-15 10:23:45 - validate_scf_parsing - INFO - No invalid headings detected
```

#### Failed Validation Log Example
```
2025-01-15 10:25:12 - validate_scf_parsing - ERROR - Configuration content mismatch detected:
2025-01-15 10:25:12 - validate_scf_parsing - ERROR - Original config length: 523456 characters
2025-01-15 10:25:12 - validate_scf_parsing - ERROR - Reconstructed config length: 523012 characters
2025-01-15 10:25:12 - validate_scf_parsing - ERROR - Detailed diff output:
2025-01-15 10:25:12 - validate_scf_parsing - ERROR - --- original_config
2025-01-15 10:25:12 - validate_scf_parsing - ERROR - +++ reconstructed_config
2025-01-15 10:25:12 - validate_scf_parsing - ERROR - @@ -1523,7 +1523,6 @@
2025-01-15 10:25:12 - validate_scf_parsing - ERROR -      pool /Common/web-pool
2025-01-15 10:25:12 - validate_scf_parsing - ERROR - -    profiles {
2025-01-15 10:25:12 - validate_scf_parsing - ERROR - -        /Common/http { }
2025-01-15 10:25:12 - validate_scf_parsing - ERROR - -    }
2025-01-15 10:25:12 - validate_scf_parsing - ERROR - [MISMATCH] Prefix 'ltm virtual' - Expected: 45, Found: 44
2025-01-15 10:25:12 - validate_scf_parsing - WARNING - Found 2 potentially invalid headings:
2025-01-15 10:25:12 - validate_scf_parsing - WARNING -   - ltm unsupported-object /Common/test {
```

### Common Validation Errors and Solutions

#### Content Mismatch Error
**Symptom**: `ValueError` with different character counts
**Cause**: Parser failed to correctly handle certain configuration patterns
**Solution**: 
- Check the diff output in the log file
- Identify the specific stanza causing issues
- Report unhandled patterns for parser updates

#### Missing Stanzas
**Symptom**: `[MISMATCH]` entries in log showing fewer found than expected
**Cause**: Parser didn't recognise certain stanza types
**Solution**:
- Review the specific prefix that's missing
- Check if it's a new or uncommon F5 object type
- May require parser enhancement for new object types

#### Duplicate Stanzas
**Symptom**: `Duplicate stanzas detected` exception
**Cause**: Parser incorrectly created multiple objects for single configuration block
**Solution**:
- Identify which stanza type is duplicated
- Usually indicates parser boundary detection issue

#### Invalid Headings
**Symptom**: `Found N potentially invalid headings` warning
**Cause**: Configuration contains non-standard or malformed stanza headers
**Solution**:
- Review listed invalid headings
- May be custom objects or syntax errors in source configuration

### When to Check the Validation Log

Always review `f5_config_validation.log` when:
- Parsing a new F5 configuration for the first time
- Configuration parsing raises exceptions
- Unexpected stanzas appear missing or duplicated
- Dependency resolution produces unexpected results
- Migrating configurations between F5 versions
- Debugging parsing issues with complex configurations

The validation log provides critical insights into parsing accuracy and helps identify edge cases that may require parser enhancements.

## Requirements

- Python 3.7+
- cryptography >= 45.0.6
- Standard library modules:
  - re (regular expressions)
  - ipaddress (IP address manipulation)
  - datetime (date/time handling)
  - collections (data structures)
  - pathlib (file path handling)
  - tarfile (tar archive extraction)
  - typing (type hints)

## Project Structure

```
f5_config_parser/
├── __init__.py
├── collection.py              # StanzaCollection class
├── change_record.py           # Change logging infrastructure
├── dependency_resolver.py     # Dependency resolution logic
├── factory.py                 # Stanza creation and parsing
├── monitored_list.py          # Change-tracking list implementation
├── validate_scf_parsing.py    # Configuration validation
├── certificates/
│   ├── __init__.py
│   ├── certificate.py         # Certificate class extending ConfigStanza
│   └── certificate_loader.py  # F5 tar extraction and parsing
├── stanza/
│   ├── __init__.py
│   ├── base.py                # Base stanza functionality
│   ├── cli_partition.py       # CLI partition configuration
│   ├── data_group.py          # Data group stanzas
│   ├── generic.py             # Generic configuration stanza
│   ├── irule.py               # iRule stanzas
│   ├── irule_parser.py        # iRule parsing utilities
│   ├── monitor.py             # Health monitor stanzas
│   ├── node.py                # Node stanzas
│   ├── partition_ip_rd_parser.py  # Partition IP route domain parsing
│   ├── pool.py                # Pool stanzas
│   ├── profile_client_ssl.py  # SSL client profile stanzas
│   ├── route.py               # Route stanzas with network dependency resolution
│   ├── selfip.py              # Self IP stanzas
│   ├── snatpool.py            # SNAT pool stanzas
│   ├── sys_file_ssl_crt.py    # SSL certificate file stanzas
│   ├── utils.py               # Shared parsing utilities
│   └── virtual_server.py      # Virtual server stanzas
└── tests/                      # Test suite
    ├── __init__.py
    ├── test_collection.py
    ├── test_dependencies.py
    ├── test_certificates.py
    └── data/              # Test data
```

## Testing

Run the test suite to ensure everything is working correctly:

```bash
# Run all tests from project root e.g ../f5_config_parser
python -m pytest

# Run tests matching a pattern
python -m pytest -k "certificate"
```

## API Documentation

TODO

### Generating Documentation Locally

To generate the API documentation locally:

```bash
# Install documentation dependencies
pip install sphinx sphinx-rtd-theme

# Generate HTML documentation
cd docs
make html

# View the documentation
open _build/html/index.html  # macOS
# or
xdg-open _build/html/index.html  # Linux
```

## Contributing

We welcome contributions! Please fork and create pull request.

## License

This project is licensed under the MIT License.

Copyright (c) 2025

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.