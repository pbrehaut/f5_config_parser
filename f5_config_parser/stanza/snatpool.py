from f5_config_parser.stanza.generic import ConfigStanza
from f5_config_parser.stanza.partition_ip_rd_parser import extract_fields
from typing import TYPE_CHECKING, List

if TYPE_CHECKING:
    from f5_config_parser.collection import StanzaCollection


class SNATPoolStanza(ConfigStanza):
    """SNAT Pool with collection-based dependency resolution"""

    def _parse_ips_to_ip_rd(self, collection: 'StanzaCollection'):
        """Parse IP address and route domain for each SNAT pool member.

        For each member in the SNAT pool, extracts the IP address using extract_fields
        and determines the route domain. If no route domain is found, falls back to
        default RD. Sets the ip_rd attribute in each member's config as a tuple
        of (address, route_domain).
        """
        members = self.parsed_config.get('members', {})

        for member_name in members.keys():
            # Use extract_fields to parse IP from member name
            parsed_fields = extract_fields(member_name, required_fields=['ip_address'])

            address = parsed_fields['ip_address']

            # Get route domain from parsed fields or use default
            rd = parsed_fields.get('route_domain')
            if rd is None:
                rd = self.get_default_rd(collection=collection)

            # Store the parsed data in a new structure for the member
            members[member_name] = {
                'address': address,
                'ip_rd': (address, rd)
            }

    def _discover_dependencies(self, collection: 'StanzaCollection') -> List[str]:
        """Discover dependencies using collection filtering"""
        dependency_paths = []

        # Member IP/route dependencies
        members = self.get_config_value('members')
        if isinstance(members, dict):
            for member_name, member_config in members.items():
                # Check for IP-based dependencies if we have parsed IP data
                if isinstance(member_config, dict) and 'ip_rd' in member_config:
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

        return dependency_paths