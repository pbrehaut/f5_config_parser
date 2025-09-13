import ipaddress
from typing import List
from f5_config_parser.stanza.generic import ConfigStanza
from f5_config_parser.stanza.utils import get_rd_from_ip
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from f5_config_parser.collection import StanzaCollection


class RouteStanza(ConfigStanza):
    """Route with IP and route domain parsing"""

    def _discover_dependencies(self, collection: 'StanzaCollection') -> List[str]:
        """Discover dependencies using collection filtering"""
        dependency_paths = []

        # Self IP dependency based on gateway IP/RD
        if hasattr(self, 'gateway_rd') and self.gateway_rd:
            # Find Self IP stanzas that contain this gateway IP/RD
            self_ip_stanzas = collection.filter(prefix=("net", "self"))
            for self_ip_stanza in self_ip_stanzas:
                if self.gateway_rd in self_ip_stanza:
                    dependency_paths.append(self_ip_stanza.full_path)

        return dependency_paths

    def __contains__(self, ip_rd_tuple: tuple[str, str]) -> bool:
        """Check if an IP address and route domain falls within this route's network.

        Args:
            ip_rd_tuple: Tuple of (ip_address, route_domain)

        Returns:
            True if the route domain matches and IP falls within the route's network subnet
        """
        if not hasattr(self, 'network_rd') or not self.network_rd:
            return False

        ip_address, route_domain = ip_rd_tuple
        route_network, route_rd = self.network_rd

        # Check route domain match first
        if route_domain != route_rd:
            return False

        # Check if IP falls within subnet
        try:
            route_net = ipaddress.IPv4Network(route_network, strict=False)
            target_ip = ipaddress.IPv4Address(ip_address)
            return target_ip in route_net
        except (ipaddress.AddressValueError, ValueError):
            return False

    def _parse_ips_to_ip_rd(self, collection: 'StanzaCollection') -> None:
        """Parse IP addresses and route domains from Route configuration.

        Extracts the network and gateway addresses from parsed config and determines
        their route domains. If network is 'default', uses '0.0.0.0/0'. If no route
        domain is found in the IP addresses, falls back to default RD.
        Sets the network_rd and gateway_rd attributes as tuples of (address, route_domain).
        """
        # Parse network
        network = self.parsed_config.get('network')
        if network == 'default':
            network = '0.0.0.0/0'

        network_rd = get_rd_from_ip(network)
        if network_rd == '':
            network_rd = self.get_default_rd(collection=collection)

        self.network_rd = (network, network_rd)

        # Parse gateway
        gateway = self.parsed_config.get('gw')
        if gateway:
            gateway_rd = get_rd_from_ip(gateway)
            if gateway_rd == '':
                gateway_rd = self.get_default_rd(collection=collection)

            self.gateway_rd = (gateway, gateway_rd)

    def __len__(self):
        """Return the subnet prefix length of the route's network.

        Returns:
            int: The prefix length of the network subnet
        """
        if not hasattr(self, 'network_rd') or not self.network_rd:
            return 0
        ip = self.network_rd[0]
        return int(ip.split('/')[1]) if '/' in ip else 32
