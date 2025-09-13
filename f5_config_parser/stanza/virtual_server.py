from f5_config_parser.stanza.generic import ConfigStanza
from f5_config_parser.stanza.partition_ip_rd_parser import extract_fields
from typing import TYPE_CHECKING, List, Dict, Any

if TYPE_CHECKING:
    from f5_config_parser.collection import StanzaCollection


class VirtualServerStanza(ConfigStanza):
    """Virtual server with collection-based dependency resolution"""

    def _do_parse(self) -> Dict[str, Any]:
        """Do additional processing for IPs after initial parsing"""
        parsed_from_base = self._parse_lines(self.config_lines, 0)[0]
        if 'destination' in parsed_from_base:
            parsed_from_base.update(
                extract_fields(parsed_from_base['destination'], required_fields=['ip_address', 'port'])
            )
        return parsed_from_base

    def _parse_ips_to_ip_rd(self, collection: 'StanzaCollection'):
        """Parse IP address and route domain from already parsed destination value.

        Checks if the IP address and rd are already parsed config and uses the route domain.
        If no route domain attribute is found, falls back to default RD.
        Sets the ip_rd attribute in parsed_config as a tuple of (address, route_domain).
        """
        rd = self.parsed_config.get('route_domain', None)
        if rd is None:
            rd = self.get_default_rd(collection=collection)

        self.parsed_config['ip_rd'] = (self.parsed_config.get('ip_address'), rd)

    def _discover_dependencies(self, collection: 'StanzaCollection') -> List[str]:
        """Discover dependencies using collection filtering"""
        dependency_paths = []

        # Self IP and Route dependency based on virtual server IP/RD
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

        # Pool dependency (exact match required)
        pool = self.get_config_value('pool')
        if pool:
            pool_path = collection.resolve_object_by_name(pool, ("ltm", "pool"))
            if pool_path:
                dependency_paths.append(pool_path)

        # Profile dependencies (search within ltm profile scope)
        profiles = self.get_config_value('profiles')
        if isinstance(profiles, dict):
            for profile_name in profiles.keys():
                profile_path = collection.resolve_object_by_name(profile_name, ("ltm", "profile"))
                if profile_path:
                    dependency_paths.append(profile_path)

        # iRule dependencies (exact match required)
        rules = self.get_config_value('rules')
        if isinstance(rules, dict):
            for rule_name in rules.keys():
                rule_path = collection.resolve_object_by_name(rule_name, ("ltm", "rule"))
                if rule_path:
                    dependency_paths.append(rule_path)

        return dependency_paths