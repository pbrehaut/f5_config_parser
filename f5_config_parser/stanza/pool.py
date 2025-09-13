from f5_config_parser.stanza.generic import ConfigStanza
from f5_config_parser.stanza.utils import _parse_monitor_expression, _is_ip_address
from f5_config_parser.stanza.partition_ip_rd_parser import extract_fields
from typing import TYPE_CHECKING, List, Dict, Any

if TYPE_CHECKING:
    from f5_config_parser.collection import StanzaCollection


class PoolStanza(ConfigStanza):
    """Pool with collection-based dependency resolution"""

    def _parse_ips_to_ip_rd(self, collection: 'StanzaCollection'):
        """Parse IP address and route domain for each pool member.

        For each member in the pool, checks if it has an IP address and extracts
        the route domain. If no route domain attribute is found, falls back to
        default RD. Sets the ip_rd attribute in each member's config as a tuple
        of (address, route_domain).
        """
        members = self.parsed_config.get('members', {})

        for member_key, member_config in members.items():
            try:
                parsed_fields = extract_fields(member_config.get('address', ""), required_fields=['ip_address'])
            except ValueError:
                print(f"Error parsing IP address for member {member_key} in pool {self.full_path}")
                continue
            address = parsed_fields['ip_address']

            # Get route domain from parsed fields or use default
            rd = parsed_fields.get('route_domain')
            if rd is None:
                rd = self.get_default_rd(collection=collection)
            member_config['ip_rd'] = (address, rd)

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

        # Member/node dependencies and IP/route dependencies
        members = self.get_config_value('members')
        if isinstance(members, dict):
            for member_name, member_config in members.items():
                # Extract node name from member (remove :port if present)
                node_name = member_name.split(':')[0]

                # Check for IP-based dependencies (Self IP or Route)
                if 'ip_rd' in member_config:
                    ip_rd = member_config['ip_rd']
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

                # Try to find node object - allow missing since member could be IP
                node_path = collection.resolve_object_by_name(node_name, ("ltm", "node"))
                if node_path:
                    dependency_paths.append(node_path)

        return dependency_paths