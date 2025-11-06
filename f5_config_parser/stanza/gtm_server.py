from f5_config_parser.stanza.generic import ConfigStanza
from f5_config_parser.stanza.partition_ip_rd_parser import extract_fields
from typing import TYPE_CHECKING, List, Dict, Tuple

if TYPE_CHECKING:
    from f5_config_parser.collection import StanzaCollection


class GTMServerStanza(ConfigStanza):
    """GTM Server with collection-based dependency resolution"""

    def _parse_ips_to_ip_rd(self, collection: 'StanzaCollection'):
        """Parse IP addresses and route domains from all devices.

        For each device, checks each address and extracts the route domain.
        If no route domain attribute is found, falls back to default RD.
        Sets the addresses_ip_rd attribute in each device's config as a dict
        mapping addresses to (address, route_domain) tuples.
        """
        devices = self.parsed_config.get('devices', {})

        for device_name, device_config in devices.items():
            addresses = device_config.get('addresses', {})
            addresses_ip_rd = {}

            for address in addresses.keys():
                # Use extract_fields to parse IP and route domain from address
                parsed_fields = extract_fields(address, required_fields=['ip_address'])

                clean_address = parsed_fields['ip_address']

                # Get route domain from parsed fields or use default
                rd = parsed_fields.get('route_domain')
                if rd is None:
                    rd = self.get_default_rd(collection=collection)

                addresses_ip_rd[address] = (clean_address, rd)

            # Store the addresses_ip_rd mapping in the device config
            if addresses_ip_rd:
                device_config['addresses_ip_rd'] = addresses_ip_rd

    def _discover_dependencies(self, collection: 'StanzaCollection') -> List[str]:
        """Discover dependencies using collection filtering"""
        dependency_paths = []

        devices = self.parsed_config.get('devices', {})

        for device_name, device_config in devices.items():
            addresses_ip_rd = device_config.get('addresses_ip_rd', {})

            for address, ip_rd in addresses_ip_rd.items():
                # First check Self IP stanzas
                self_ip_stanzas = collection.filter(prefix=("net", "self"))
                ip_found = False
                for self_ip_stanza in self_ip_stanzas:
                    if ip_rd in self_ip_stanza:
                        if self_ip_stanza.full_path not in dependency_paths:
                            dependency_paths.append(self_ip_stanza.full_path)
                        ip_found = True

                # If no Self IP match, check Route stanzas for longest match
                if not ip_found:
                    matching_route_stanzas = []
                    route_stanzas = collection.filter(prefix=("net", "route"))
                    for route_stanza in route_stanzas:
                        if ip_rd in route_stanza:
                            matching_route_stanzas.append(route_stanza)
                    if matching_route_stanzas:
                        best_route_stanza = max(matching_route_stanzas, key=len)
                        if best_route_stanza.full_path not in dependency_paths:
                            dependency_paths.append(best_route_stanza.full_path)

        return dependency_paths

    def _discover_dependency_map(self, collection: 'StanzaCollection') -> Dict[Tuple[str, str], List[str]]:
        """Map config values to their dependencies using tuple keys (attribute_name, value)"""
        dependency_map = {}

        devices = self.parsed_config.get('devices', {})

        for device_name, device_config in devices.items():
            addresses_ip_rd = device_config.get('addresses_ip_rd', {})

            for address, ip_rd in addresses_ip_rd.items():
                address_dependencies = []

                # First check Self IP stanzas
                self_ip_stanzas = collection.filter(prefix=("net", "self"))
                ip_found = False
                for self_ip_stanza in self_ip_stanzas:
                    if ip_rd in self_ip_stanza:
                        address_dependencies.append(self_ip_stanza.full_path)
                        ip_found = True

                # If no Self IP match, check Route stanzas for longest match
                if not ip_found:
                    matching_route_stanzas = []
                    route_stanzas = collection.filter(prefix=("net", "route"))
                    for route_stanza in route_stanzas:
                        if ip_rd in route_stanza:
                            matching_route_stanzas.append(route_stanza)
                    if matching_route_stanzas:
                        best_route_stanza = max(matching_route_stanzas, key=len)
                        address_dependencies.append(best_route_stanza.full_path)

                # Add to map if we found any dependencies for this address
                if address_dependencies:
                    device_address_key = f"{device_name}:{address}"
                    dependency_map[("devices", device_address_key)] = address_dependencies

        return dependency_map