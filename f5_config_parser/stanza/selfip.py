import ipaddress
from f5_config_parser.stanza.generic import ConfigStanza
from f5_config_parser.stanza.utils import get_rd_from_ip
from typing import TYPE_CHECKING, List

if TYPE_CHECKING:
    from f5_config_parser.collection import StanzaCollection


class SelfIPStanza(ConfigStanza):
    """Self IP with collection-based dependency resolution"""

    def __contains__(self, ip_rd_tuple: tuple[str, str]) -> bool:
        """Check if an IP address and route domain falls within this Self IP's network.

        Args:
            ip_rd_tuple: Tuple of (ip_address, route_domain)

        Returns:
            True if the route domain matches and IP falls within the Self IP's subnet
        """
        if not hasattr(self, 'ip_rd') or not self.ip_rd:
            return False

        ip_address, route_domain = ip_rd_tuple
        self_network, self_rd = self.ip_rd

        # Check route domain match first
        if route_domain != self_rd:
            return False

        # Check if IP falls within subnet
        try:
            self_net = ipaddress.IPv4Network(self_network, strict=False)
            target_ip = ipaddress.IPv4Address(ip_address)
            return target_ip in self_net
        except (ipaddress.AddressValueError, ValueError):
            return False

    def _discover_dependencies(self, collection: 'StanzaCollection') -> List[str]:
        """Discover dependencies using collection filtering"""
        dependency_paths = []

        # VLAN dependency (exact match required)
        vlan = self.get_config_value('vlan')
        if vlan:
            vlan_path = collection.resolve_object_by_name(vlan, ("net", "vlan"))
            if vlan_path:
                dependency_paths.append(vlan_path)

        return dependency_paths

    def _parse_ips_to_ip_rd(self, collection: 'StanzaCollection'):
        """Parse IP address and route domain from Self IP configuration.

        Extracts the IP address from parsed config and determines the route domain.
        If no route domain is found in the IP address, falls back to default RD.
        Sets the ip_rd attribute as a tuple of (address, route_domain).
        """
        rd = get_rd_from_ip(self.parsed_config.get('address'))
        if rd == '':
            rd = self.get_default_rd(collection=collection)

        self.ip_rd = (self.parsed_config.get('address'), rd)