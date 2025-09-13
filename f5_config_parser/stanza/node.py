from f5_config_parser.stanza.generic import ConfigStanza
from f5_config_parser.stanza.utils import _parse_monitor_expression
from f5_config_parser.stanza.partition_ip_rd_parser import extract_fields
from typing import TYPE_CHECKING, List

if TYPE_CHECKING:
    from f5_config_parser.collection import StanzaCollection


class NodeStanza(ConfigStanza):
    """Node with collection-based dependency resolution"""

    def _parse_ips_to_ip_rd(self, collection: 'StanzaCollection'):
        """Parse IP address and route domain from node address.

        Checks if the node has an IP address and extracts the route domain.
        If no route domain attribute is found, falls back to default RD.
        Sets the ip_rd attribute as a tuple of (address, route_domain).
        """
        address = self.parsed_config.get('address')

        # Only process if we have an address
        if address:
            # Use extract_fields to parse IP and route domain from address
            parsed_fields = extract_fields(address, required_fields=['ip_address'])

            clean_address = parsed_fields['ip_address']

            # Get route domain from parsed fields or use default
            rd = parsed_fields.get('route_domain')
            if rd is None:
                rd = self.get_default_rd(collection=collection)

            # Store the clean IP address and route domain info
            self.parsed_config['address'] = clean_address
            self.parsed_config['ip_rd'] = (clean_address, rd)

    def _discover_dependencies(self, collection: 'StanzaCollection') -> List[str]:
        """Discover dependencies using collection filtering"""
        dependency_paths = []

        # Monitor dependency (search within ltm monitor scope)
        monitor = self.get_config_value('monitor')
        if monitor:
            # Handle compound monitor expressions like "mon-a and mon-b"
            monitor_names = _parse_monitor_expression(monitor)
            for monitor_name in monitor_names:
                monitor_path = collection.resolve_object_by_name(monitor_name, ("ltm", "monitor"))
                if monitor_path:
                    dependency_paths.append(monitor_path)

        # Self IP and Route dependency based on node IP/RD
        if 'ip_rd' in self.parsed_config:
            ip_rd = self.parsed_config['ip_rd']
            # First check Self IP stanzas
            self_ip_stanzas = collection.filter(prefix=("net", "self"))
            ip_found = False
            for self_ip_stanza in self_ip_stanzas:
                if ip_rd in self_ip_stanza:
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
                    dependency_paths.append(best_route_stanza.full_path)

        return dependency_paths